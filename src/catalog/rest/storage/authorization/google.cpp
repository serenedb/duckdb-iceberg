#include "catalog/rest/storage/authorization/google.hpp"

#include "duckdb/common/exception/http_exception.hpp"
#include "duckdb/common/types/value.hpp"

#include "catalog/rest/api/api_utils.hpp"
#include "rest_catalog/objects/oauth_token_response.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <absl/strings/escaping.h>

#include <chrono>
#include <memory>

namespace duckdb {

namespace {

constexpr const char *JWT_BEARER_GRANT_BODY =
    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=";
constexpr const char *METADATA_HOST_ENV = "GCE_METADATA_HOST";
constexpr const char *METADATA_DEFAULT_HOST = "metadata.google.internal";
constexpr const char *METADATA_TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token";

using Config = GoogleAuthorization::Config;
using Mode = GoogleAuthorization::Mode;

struct MintedToken {
	string access_token;
	int32_t expires_in = 0;
};

const case_insensitive_map_view_t<LogicalType> &GoogleSecretOptions() {
	static const case_insensitive_map_view_t<LogicalType> options {
	    {"client_email", LogicalType::VARCHAR},
	    {"private_key", LogicalType::VARCHAR},
	    {"private_key_id", LogicalType::VARCHAR},
	    {"token_uri", LogicalType::VARCHAR},
	    {"oauth2_scope", LogicalType::VARCHAR},
	    {"endpoint", LogicalType::VARCHAR},
	    {"extra_http_headers", LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)}};
	return options;
}

string JwtHeader(const Config &config) {
	std::unique_ptr<yyjson_mut_doc, YyjsonDocDeleter> doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	yyjson_mut_obj_add_str(doc.get(), root, "alg", "RS256");
	yyjson_mut_obj_add_str(doc.get(), root, "typ", "JWT");
	if (!config.private_key_id.empty()) {
		yyjson_mut_obj_add_str(doc.get(), root, "kid", config.private_key_id.c_str());
	}
	return ICUtils::JsonToString(std::move(doc));
}

string JwtClaims(const Config &config, int64_t now) {
	std::unique_ptr<yyjson_mut_doc, YyjsonDocDeleter> doc(yyjson_mut_doc_new(nullptr));
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	yyjson_mut_obj_add_str(doc.get(), root, "iss", config.client_email.c_str());
	yyjson_mut_obj_add_str(doc.get(), root, "scope", config.scope.c_str());
	yyjson_mut_obj_add_str(doc.get(), root, "aud", config.token_uri.c_str());
	yyjson_mut_obj_add_int(doc.get(), root, "iat", now);
	yyjson_mut_obj_add_int(doc.get(), root, "exp", now + 3600);
	return ICUtils::JsonToString(std::move(doc));
}

string OpenSslError() {
	auto reason = ERR_reason_error_string(ERR_get_error());
	return reason ? reason : "unknown OpenSSL error";
}

string SignRs256(const string &private_key_pem, const string &message) {
	ERR_clear_error();
	std::unique_ptr<BIO, decltype(&BIO_free)> bio(
	    BIO_new_mem_buf(private_key_pem.data(), static_cast<int>(private_key_pem.size())), BIO_free);
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
	    PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (!pkey) {
		throw InvalidConfigurationException(
		    "Could not parse 'private_key' (%s). Expected the PEM private key of a service-account key file; escaped "
		    "newlines ('\\n') are accepted, E'...' quoting is not needed",
		    OpenSslError());
	}
	if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA) {
		throw InvalidConfigurationException(
		    "'private_key' is not an RSA key; Google service-account keys use RSA (RS256)");
	}
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	auto data = reinterpret_cast<const unsigned char *>(message.data());
	size_t signature_length = 0;
	if (!md_ctx || EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1 ||
	    EVP_DigestSign(md_ctx.get(), nullptr, &signature_length, data, message.size()) != 1) {
		throw InvalidConfigurationException("Failed to sign the service-account JWT (%s)", OpenSslError());
	}
	string signature(signature_length, '\0');
	if (EVP_DigestSign(md_ctx.get(), reinterpret_cast<unsigned char *>(signature.data()), &signature_length, data,
	                   message.size()) != 1) {
		throw InvalidConfigurationException("Failed to sign the service-account JWT (%s)", OpenSslError());
	}
	signature.resize(signature_length);
	return signature;
}

rest_api_objects::OAuthTokenResponse ParseTokenResponse(const string &uri, HTTPResponse &response) {
	if (response.status < HTTPStatusCode::OK_200 || response.status >= HTTPStatusCode::MultipleChoices_300) {
		throw InvalidConfigurationException("Could not get token from %s: HTTP %s - %s", uri,
		                                    EnumUtil::ToString(response.status), response.body);
	}
	std::unique_ptr<yyjson_doc, YyjsonDocDeleter> doc(yyjson_read(response.body.c_str(), response.body.size(), 0));
	if (!doc) {
		throw InvalidConfigurationException("Could not get token from %s: server returned invalid JSON", uri);
	}
	auto token_response = rest_api_objects::OAuthTokenResponse::FromJSON(yyjson_doc_get_root(doc.get()));
	if (!StringUtil::CIEquals(token_response.token_type, "bearer")) {
		throw NotImplementedException(
		    "token_type return value '%s' is not supported, only supports 'bearer' currently.",
		    token_response.token_type);
	}
	return token_response;
}

MintedToken FetchToken(ClientContext &context, RequestType request_type, const string &url,
                       IRCEndpointBuilder &endpoint_builder, HTTPHeaders &headers, const string &body,
                       const string &transport_error_hint) {
	unique_ptr<HTTPResponse> response;
	try {
		response = APIUtils::Request(request_type, nullptr, context, endpoint_builder, headers, body);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		throw InvalidConfigurationException("Could not get token from %s: %s%s", url, error.RawMessage(),
		                                    transport_error_hint);
	}
	auto token_response = ParseTokenResponse(url, *response);
	return {token_response.access_token, token_response.expires_in.value_or(0)};
}

MintedToken MintServiceAccountToken(ClientContext &context, const Config &config) {
	auto now =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	auto signing_input = absl::WebSafeBase64Escape(JwtHeader(config)) + "." +
	                     absl::WebSafeBase64Escape(JwtClaims(config, static_cast<int64_t>(now)));
	auto jwt = signing_input + "." + absl::WebSafeBase64Escape(SignRs256(config.private_key, signing_input));

	//! grant_type is pre-encoded and the assertion is base64url, so the body needs no further form-encoding
	auto post_data = JWT_BEARER_GRANT_BODY + jwt;
	HTTPHeaders headers(*context.db);
	headers.Insert("Content-Type", "application/x-www-form-urlencoded");

	auto endpoint_builder = IRCEndpointBuilder::FromURL(config.token_uri);
	return FetchToken(context, RequestType::POST_REQUEST, config.token_uri, endpoint_builder, headers, post_data, "");
}

MintedToken MintMetadataToken(ClientContext &context, const Config &config) {
	HTTPHeaders headers(*context.db);
	headers.Insert("Metadata-Flavor", "Google");

	auto endpoint_builder = IRCEndpointBuilder::FromURL(config.token_uri);
	if (config.scope != GoogleAuthorization::DEFAULT_SCOPE) {
		endpoint_builder.SetParam("scopes",
		                          IRCPathComponent::RegularComponent(StringUtil::Replace(config.scope, " ", ",")));
	}
	return FetchToken(context, RequestType::GET_REQUEST, config.token_uri, endpoint_builder, headers, "",
	                  ". PROVIDER google without 'client_email'+'private_key' only works when running on Google Cloud "
	                  "(GCE/GKE)");
}

MintedToken MintToken(ClientContext &context, const Config &config) {
	if (config.mode == Mode::METADATA_SERVER) {
		return MintMetadataToken(context, config);
	}
	return MintServiceAccountToken(context, config);
}

Config ConfigFromSecret(const KeyValueSecret &secret) {
	Config config;
	auto client_email = secret.TryGetValue("client_email");
	if (!client_email.IsNull()) {
		config.client_email = client_email.ToString();
	}
	auto private_key = secret.TryGetValue("private_key");
	if (!private_key.IsNull()) {
		config.private_key = private_key.ToString();
	}
	auto private_key_id = secret.TryGetValue("private_key_id");
	if (!private_key_id.IsNull()) {
		config.private_key_id = private_key_id.ToString();
	}
	auto token_uri = secret.TryGetValue("token_uri");
	if (!token_uri.IsNull()) {
		config.token_uri = token_uri.ToString();
	}
	auto scope = secret.TryGetValue("oauth2_scope");
	if (!scope.IsNull()) {
		config.scope = StringUtil::Replace(scope.ToString(), ",", " ");
	}
	if (config.client_email.empty() != config.private_key.empty()) {
		throw InvalidInputException(
		    "Google service-account credentials require both 'client_email' and 'private_key'. Provide both (from the "
		    "service-account key file), or neither to use the GCE metadata server");
	}
	if (config.client_email.empty()) {
		config.mode = Mode::METADATA_SERVER;
		if (token_uri.IsNull()) {
			auto host = FileSystem::GetEnvVariable(METADATA_HOST_ENV);
			if (host.empty()) {
				host = METADATA_DEFAULT_HOST;
			}
			config.token_uri = StringUtil::Format("http://%s%s", host, METADATA_TOKEN_PATH);
		}
	} else {
		config.mode = Mode::SERVICE_ACCOUNT;
	}
	return config;
}

} // namespace

GoogleAuthorization::GoogleAuthorization(AttachedDatabase &db, Config config_p)
    : OAuth2Authorization(db), config(std::move(config_p)) {
	uri = config.token_uri;
	scope = config.scope;
}

unique_ptr<BaseSecret> GoogleAuthorization::CreateCatalogSecretFunction(ClientContext &context,
                                                                        CreateSecretInput &input) {
	vector<string> prefix_paths;
	auto result = make_uniq<KeyValueSecret>(prefix_paths, "iceberg", "google", input.name);
	result->redact_keys = {"token", "private_key"};

	auto &accepted_parameters = GoogleSecretOptions();
	for (const auto &named_param : input.options) {
		auto &param_name = named_param.first;
		if (!accepted_parameters.count(param_name)) {
			throw InvalidInputException("Unknown named parameter passed to CreateGoogleSecretFunction: %s", param_name);
		}
		if (StringUtil::CIEquals(param_name, "extra_http_headers")) {
			result->secret_map[Identifier(param_name)] = named_param.second;
		} else if (StringUtil::CIEquals(param_name, "private_key")) {
			result->secret_map[Identifier(param_name)] =
			    StringUtil::Replace(named_param.second.ToString(), "\\n", "\n");
		} else {
			result->secret_map[Identifier(param_name)] = named_param.second.ToString();
		}
	}

	auto minted = MintToken(context, ConfigFromSecret(*result));
	result->secret_map["token"] = minted.access_token;
	if (minted.expires_in > 0) {
		result->secret_map["expires_in"] = Value::INTEGER(minted.expires_in);
	}
	return std::move(result);
}

void GoogleAuthorization::SetCatalogSecretParameters(CreateSecretFunction &function) {
	for (auto &option : GoogleSecretOptions()) {
		function.named_parameters[Identifier(option.first)] = option.second;
	}
}

unique_ptr<GoogleAuthorization> GoogleAuthorization::FromSecret(AttachedDatabase &db, ClientContext &context,
                                                                IcebergAttachOptions &input,
                                                                const KeyValueSecret &secret) {
	auto result = make_uniq<GoogleAuthorization>(db, ConfigFromSecret(secret));

	if (input.endpoint.empty()) {
		auto endpoint_from_secret = secret.TryGetValue("endpoint");
		if (endpoint_from_secret.IsNull()) {
			throw InvalidConfigurationException(
			    "No 'endpoint' was given to attach, and no 'endpoint' could be retrieved from the ICEBERG secret!");
		}
		input.endpoint = endpoint_from_secret.ToString();
	}
	IcebergAuthorization::ParseExtraHttpHeaders(secret.TryGetValue("extra_http_headers"), result->extra_http_headers);

	auto token = secret.TryGetValue("token");
	if (!token.IsNull()) {
		auto expires_in = secret.TryGetValue("expires_in");
		int32_t expires_in_seconds = 0;
		if (!expires_in.IsNull() && expires_in.type().id() == LogicalTypeId::INTEGER) {
			expires_in_seconds = expires_in.GetValue<int32_t>();
		}
		result->UpdateTokenState(token.ToString(), expires_in_seconds, "");
	} else {
		auto minted = MintToken(context, result->config);
		result->UpdateTokenState(minted.access_token, minted.expires_in, "");
	}
	return result;
}

bool GoogleAuthorization::CanRefreshUnlocked(std::lock_guard<std::mutex> &) const {
	return true;
}

void GoogleAuthorization::RefreshAccessTokenUnlocked(ClientContext &context, std::lock_guard<std::mutex> &) {
	auto minted = MintToken(context, config);
	UpdateTokenState(minted.access_token, minted.expires_in, "");
}

} // namespace duckdb

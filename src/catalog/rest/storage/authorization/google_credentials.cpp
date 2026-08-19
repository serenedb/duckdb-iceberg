
#include "catalog/rest/storage/authorization/google_credentials.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"

#include "catalog/rest/api/api_utils.hpp"
#include "catalog/rest/api/catalog_utils.hpp"
#include "catalog/rest/storage/authorization/oauth2.hpp"

#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

#include "duckdb/common/enum_util.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <random>

namespace duckdb {

namespace {

//! mbedtls needs an entropy callback for RSA blinding during signing;
//! std::random_device is /dev/urandom-backed on the platforms we target.
static int GoogleRng(void *, unsigned char *output, size_t len) {
	static thread_local std::random_device rd;
	size_t written = 0;
	while (written < len) {
		auto value = rd();
		auto chunk = std::min(sizeof(value), len - written);
		std::memcpy(output + written, &value, chunk);
		written += chunk;
	}
	return 0;
}

static string Base64UrlEncode(const string &input) {
	size_t required = 0;
	mbedtls_base64_encode(nullptr, 0, &required, reinterpret_cast<const unsigned char *>(input.data()), input.size());
	string out(required, '\0');
	size_t olen = 0;
	if (mbedtls_base64_encode(reinterpret_cast<unsigned char *>(&out[0]), out.size(), &olen,
	                          reinterpret_cast<const unsigned char *>(input.data()), input.size()) != 0) {
		throw InternalException("Base64 encoding failed while building a Google JWT");
	}
	out.resize(olen);
	for (auto &c : out) {
		if (c == '+') {
			c = '-';
		} else if (c == '/') {
			c = '_';
		}
	}
	while (!out.empty() && out.back() == '=') {
		out.pop_back();
	}
	return out;
}

static string WriteJsonObject(const std::function<void(yyjson_mut_doc *, yyjson_mut_val *)> &fill) {
	auto *doc = yyjson_mut_doc_new(nullptr);
	auto *root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);
	fill(doc, root);
	auto *json = yyjson_mut_write(doc, 0, nullptr);
	yyjson_mut_doc_free(doc);
	if (!json) {
		throw InternalException("Failed to serialize JSON while building a Google JWT");
	}
	string result(json);
	free(json);
	return result;
}

static rest_api_objects::OAuthTokenResponse ParseTokenResponse(const HTTPResponse &response, const string &source) {
	std::unique_ptr<yyjson_doc, YyjsonDocDeleter> doc(yyjson_read(response.body.c_str(), response.body.size(), 0));
	if (!doc) {
		throw InvalidConfigurationException("Could not get token from %s: response is not valid JSON", source);
	}
	auto *root = yyjson_doc_get_root(doc.get());
	auto token_response = rest_api_objects::OAuthTokenResponse::FromJSON(root);
	if (!StringUtil::CIEquals(token_response.token_type, "bearer")) {
		throw NotImplementedException("token_type return value '%s' is not supported, only supports 'bearer' currently.",
		                              token_response.token_type);
	}
	return token_response;
}

} // namespace

string GoogleCredentials::BuildSignedJwt(const GoogleServiceAccountKey &key, const string &scope) {
	auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	               .count();

	auto header_json = WriteJsonObject([&](yyjson_mut_doc *doc, yyjson_mut_val *root) {
		yyjson_mut_obj_add_str(doc, root, "alg", "RS256");
		yyjson_mut_obj_add_str(doc, root, "typ", "JWT");
		if (!key.private_key_id.empty()) {
			yyjson_mut_obj_add_strcpy(doc, root, "kid", key.private_key_id.c_str());
		}
	});
	auto claims_json = WriteJsonObject([&](yyjson_mut_doc *doc, yyjson_mut_val *root) {
		yyjson_mut_obj_add_strcpy(doc, root, "iss", key.client_email.c_str());
		yyjson_mut_obj_add_strcpy(doc, root, "scope", scope.c_str());
		yyjson_mut_obj_add_strcpy(doc, root, "aud", key.token_uri.c_str());
		// 30s of slack against clock skew between us and Google
		yyjson_mut_obj_add_int(doc, root, "iat", now - 30);
		yyjson_mut_obj_add_int(doc, root, "exp", now + 3600);
	});

	auto signing_input = Base64UrlEncode(header_json) + "." + Base64UrlEncode(claims_json);

	unsigned char hash[32];
	if (mbedtls_sha256(reinterpret_cast<const unsigned char *>(signing_input.data()), signing_input.size(), hash, 0) !=
	    0) {
		throw InternalException("SHA-256 failed while building a Google JWT");
	}

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	// keylen must include the '\0' for PEM input
	int ret = mbedtls_pk_parse_key(&pk, reinterpret_cast<const unsigned char *>(key.private_key.c_str()),
	                               key.private_key.size() + 1, nullptr, 0, GoogleRng, nullptr);
	if (ret != 0) {
		mbedtls_pk_free(&pk);
		throw InvalidConfigurationException("Could not parse 'private_key' as a PEM private key (mbedtls error -0x%04x)",
		                                    static_cast<unsigned>(-ret));
	}
	unsigned char sig[1024];
	size_t sig_len = 0;
	ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sizeof(sig), &sig_len, GoogleRng, nullptr);
	mbedtls_pk_free(&pk);
	if (ret != 0) {
		throw InvalidConfigurationException("Could not sign the Google JWT with 'private_key' (mbedtls error -0x%04x)",
		                                    static_cast<unsigned>(-ret));
	}
	return signing_input + "." + Base64UrlEncode(string(reinterpret_cast<char *>(sig), sig_len));
}

rest_api_objects::OAuthTokenResponse GoogleCredentials::FetchMetadataToken(ClientContext &context) {
	const char *host_env = std::getenv("GCE_METADATA_HOST");
	string host = host_env && host_env[0] ? host_env : "metadata.google.internal";
	auto url = StringUtil::Format("http://%s/computeMetadata/v1/instance/service-accounts/default/token", host);

	auto endpoint_builder = IRCEndpointBuilder::FromURL(url);
	HTTPHeaders headers(*context.db);
	headers.Insert("Metadata-Flavor", "Google");

	unique_ptr<HTTPResponse> response;
	try {
		response = APIUtils::Request(RequestType::GET_REQUEST, nullptr, context, endpoint_builder, headers, "");
	} catch (std::exception &ex) {
		ErrorData error(ex);
		throw InvalidConfigurationException(
		    "Could not reach the GCE metadata server at '%s' (is this host running on Google Cloud?): %s", host,
		    error.RawMessage());
	}
	if (response->status < HTTPStatusCode::OK_200 || response->status >= HTTPStatusCode::MultipleChoices_300) {
		throw InvalidConfigurationException("Could not get token from the GCE metadata server at '%s': HTTP %s - %s",
		                                    host, EnumUtil::ToString(response->status), response->body);
	}
	return ParseTokenResponse(*response, "the GCE metadata server");
}

unique_ptr<BaseSecret> GoogleCredentials::CreateGoogleSecretFunction(ClientContext &context, CreateSecretInput &input) {
	auto result = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);

	string client_email;
	string private_key;
	string private_key_id;
	string token_uri;
	string oauth2_scope = DEFAULT_SCOPE;
	for (const auto &named_param : input.options) {
		auto lower_name = StringUtil::Lower(named_param.first);
		if (lower_name == "client_email") {
			client_email = named_param.second.ToString();
		} else if (lower_name == "private_key") {
			private_key = named_param.second.ToString();
		} else if (lower_name == "private_key_id") {
			private_key_id = named_param.second.ToString();
		} else if (lower_name == "token_uri") {
			token_uri = named_param.second.ToString();
		} else if (lower_name == "oauth2_scope") {
			oauth2_scope = named_param.second.ToString();
		} else if (lower_name == "endpoint") {
			result->secret_map["endpoint"] = named_param.second.ToString();
		} else if (lower_name == "extra_http_headers") {
			result->secret_map["extra_http_headers"] = named_param.second;
		} else {
			throw InvalidInputException("Unknown named parameter passed to CreateGoogleSecretFunction: %s", lower_name);
		}
	}
	bool has_fields = !client_email.empty() || !private_key.empty() || !private_key_id.empty() || !token_uri.empty();

	rest_api_objects::OAuthTokenResponse token_response;
	if (has_fields) {
		if (client_email.empty() || private_key.empty()) {
			throw InvalidInputException(
			    "service-account credentials require both 'client_email' and 'private_key'");
		}
		GoogleServiceAccountKey key;
		key.client_email = client_email;
		// Pasted straight out of a key JSON, the PEM carries literal \n sequences;
		// without a JSON parser in the path we unescape them here (PEM never contains a backslash).
		key.private_key = StringUtil::Replace(private_key, "\\n", "\n");
		key.private_key_id = private_key_id;
		key.token_uri = token_uri.empty() ? DEFAULT_TOKEN_URI : token_uri;

		auto assertion = BuildSignedJwt(key, oauth2_scope);
		token_response = OAuth2Authorization::FetchJwtBearerToken(context, key.token_uri, assertion);
		result->secret_map["oauth2_grant_type"] = Value(SERVICE_ACCOUNT_GRANT);
		result->secret_map["client_email"] = Value(key.client_email);
		result->secret_map["private_key"] = Value(key.private_key);
		if (!key.private_key_id.empty()) {
			result->secret_map["private_key_id"] = Value(key.private_key_id);
		}
		result->secret_map["token_uri"] = Value(key.token_uri);
	} else {
		token_response = FetchMetadataToken(context);
		result->secret_map["oauth2_grant_type"] = Value(METADATA_GRANT);
	}
	result->secret_map["oauth2_scope"] = Value(oauth2_scope);
	result->secret_map["token"] = Value(token_response.access_token);
	if (token_response.expires_in) {
		result->secret_map["expires_in"] = Value::INTEGER(static_cast<int32_t>(*token_response.expires_in));
	}
	result->redact_keys = {"token", "private_key"};
	return std::move(result);
}

unique_ptr<OAuth2Authorization> GoogleCredentials::MakeAuthorization(AttachedDatabase &db,
                                                                     const KeyValueSecret &kv_secret) {
	auto result = make_uniq<GoogleAuthorization>(db);
	auto get_string = [&](const char *name) -> string {
		auto val = kv_secret.TryGetValue(name);
		return val.IsNull() ? string() : val.ToString();
	};
	result->key.client_email = get_string("client_email");
	result->key.private_key = get_string("private_key");
	result->key.private_key_id = get_string("private_key_id");
	result->key.token_uri = get_string("token_uri");
	if (result->key.token_uri.empty()) {
		result->key.token_uri = GoogleCredentials::DEFAULT_TOKEN_URI;
	}
	return std::move(result);
}

bool GoogleAuthorization::CanRefreshUnlocked(std::lock_guard<std::mutex> &lock) const {
	(void)lock;
	if (grant_type == GoogleCredentials::METADATA_GRANT) {
		return true;
	}
	return !key.client_email.empty() && !key.private_key.empty();
}

void GoogleAuthorization::RefreshAccessTokenUnlocked(ClientContext &context, std::lock_guard<std::mutex> &lock) {
	(void)lock;
	rest_api_objects::OAuthTokenResponse token_response;
	if (grant_type == GoogleCredentials::METADATA_GRANT) {
		token_response = GoogleCredentials::FetchMetadataToken(context);
	} else {
		auto assertion = GoogleCredentials::BuildSignedJwt(key, scope);
		token_response = FetchJwtBearerToken(context, key.token_uri, assertion);
	}
	UpdateTokenState(token_response.access_token, token_response.expires_in.value_or(0), "");
}

void GoogleCredentials::SetGoogleSecretParameters(CreateSecretFunction &function) {
	function.named_parameters[Identifier("client_email")] = LogicalType::VARCHAR;
	function.named_parameters[Identifier("private_key")] = LogicalType::VARCHAR;
	function.named_parameters[Identifier("private_key_id")] = LogicalType::VARCHAR;
	function.named_parameters[Identifier("token_uri")] = LogicalType::VARCHAR;
	function.named_parameters[Identifier("oauth2_scope")] = LogicalType::VARCHAR;
	function.named_parameters[Identifier("endpoint")] = LogicalType::VARCHAR;
	function.named_parameters[Identifier("extra_http_headers")] = LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);
}

} // namespace duckdb

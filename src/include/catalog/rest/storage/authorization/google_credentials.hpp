#pragma once

#include "duckdb/common/string.hpp"
#include "duckdb/main/secret/secret.hpp"

#include "catalog/rest/storage/authorization/oauth2.hpp"
#include "rest_catalog/objects/oauth_token_response.hpp"

namespace duckdb {

class ClientContext;

//! Google service-account credentials, as the per-field values from the key
//! produced by `gcloud iam service-accounts keys create`.
struct GoogleServiceAccountKey {
	string client_email;
	string private_key;
	string private_key_id;
	string token_uri;
};

class GoogleCredentials {
public:
	static constexpr const char *JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
	static constexpr const char *DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
	static constexpr const char *DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
	//! Internal oauth2_grant_type markers selecting the Google token sources
	static constexpr const char *SERVICE_ACCOUNT_GRANT = "google_service_account";
	static constexpr const char *METADATA_GRANT = "google_metadata";

	//! Build the RS256-signed JWT assertion for the service-account token exchange (RFC 7523).
	static string BuildSignedJwt(const GoogleServiceAccountKey &key, const string &scope);
	//! Fetch a token for the attached service account from the GCE/GKE metadata server.
	//! Honors GCE_METADATA_HOST (Google client-library convention) for testability.
	static rest_api_objects::OAuthTokenResponse FetchMetadataToken(ClientContext &context);

	//! CREATE SECRET (TYPE ICEBERG, PROVIDER google, ...) implementation
	static unique_ptr<BaseSecret> CreateGoogleSecretFunction(ClientContext &context, CreateSecretInput &input);
	static void SetGoogleSecretParameters(CreateSecretFunction &function);

	//! Construct a GoogleAuthorization from a PROVIDER google secret
	static unique_ptr<OAuth2Authorization> MakeAuthorization(AttachedDatabase &db, const KeyValueSecret &kv_secret);
};

//! Google catalog authorization: standard OAuth2 bearer transport, tokens
//! minted from a service-account key (JWT-bearer) or the GCE metadata server.
class GoogleAuthorization : public OAuth2Authorization {
public:
	explicit GoogleAuthorization(AttachedDatabase &db) : OAuth2Authorization(db) {
	}

	GoogleServiceAccountKey key;

protected:
	bool CanRefreshUnlocked(std::lock_guard<std::mutex> &lock) const override;
	void RefreshAccessTokenUnlocked(ClientContext &context, std::lock_guard<std::mutex> &lock) override;
};

} // namespace duckdb

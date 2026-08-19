#pragma once

#include "catalog/rest/storage/authorization/oauth2.hpp"

namespace duckdb {

//! Google service-account credentials: the fields of a key produced by
//! `gcloud iam service-accounts keys create`.
struct GoogleServiceAccountKey {
	string client_email;
	string private_key;
	string private_key_id;
	string token_uri;
};

//! Google Cloud catalog authorization: standard OAuth2 bearer transport,
//! tokens minted from a service-account key (RFC 7523 JWT-bearer exchange)
//! or from the GCE/GKE metadata server when no key is configured.
class GoogleAuthorization : public OAuth2Authorization {
public:
	static constexpr const char *PROVIDER = "google";
	static constexpr const char *DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
	static constexpr const char *DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";

	enum class Mode : uint8_t { SERVICE_ACCOUNT, METADATA_SERVER };

	GoogleAuthorization(AttachedDatabase &db, Mode mode, GoogleServiceAccountKey key);

	//! Construct from a PROVIDER google secret (at ATTACH time)
	static unique_ptr<OAuth2Authorization> FromSecret(AttachedDatabase &db, const KeyValueSecret &kv_secret);

	//! CREATE SECRET (TYPE ICEBERG, PROVIDER google, ...) implementation
	static unique_ptr<BaseSecret> CreateSecret(ClientContext &context, CreateSecretInput &input);
	static void SetSecretParameters(CreateSecretFunction &function);

private:
	//! Mint a token for the given mode; used by both CreateSecret and refresh
	static rest_api_objects::OAuthTokenResponse MintToken(ClientContext &context, Mode mode,
	                                                      const GoogleServiceAccountKey &key, const string &scope);

	bool CanRefreshUnlocked(std::lock_guard<std::mutex> &lock) const override;
	void RefreshAccessTokenUnlocked(ClientContext &context, std::lock_guard<std::mutex> &lock) override;

	Mode mode;
	GoogleServiceAccountKey key;
};

} // namespace duckdb

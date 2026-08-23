#pragma once

#include "catalog/rest/storage/authorization/oauth2.hpp"

namespace duckdb {

class GoogleAuthorization : public OAuth2Authorization {
public:
	static constexpr const char *DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
	static constexpr const char *DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

	enum class Mode : uint8_t { SERVICE_ACCOUNT, METADATA_SERVER };

	//! Resolved minting configuration: in SERVICE_ACCOUNT mode token_uri is Google's oauth endpoint,
	//! in METADATA_SERVER mode it is the metadata server's token URL
	struct Config {
		Mode mode = Mode::METADATA_SERVER;
		string client_email;
		string private_key;
		string private_key_id;
		string token_uri = DEFAULT_TOKEN_URI;
		string scope = DEFAULT_SCOPE;
	};

public:
	GoogleAuthorization(AttachedDatabase &db, Config config);

public:
	static unique_ptr<BaseSecret> CreateCatalogSecretFunction(ClientContext &context, CreateSecretInput &input);
	static void SetCatalogSecretParameters(CreateSecretFunction &function);
	static unique_ptr<GoogleAuthorization> FromSecret(AttachedDatabase &db, ClientContext &context,
	                                                  IcebergAttachOptions &input, const KeyValueSecret &secret);

protected:
	bool CanRefreshUnlocked(std::lock_guard<std::mutex> &lock) const override;
	void RefreshAccessTokenUnlocked(ClientContext &context, std::lock_guard<std::mutex> &lock) override;

private:
	Config config;
};

} // namespace duckdb

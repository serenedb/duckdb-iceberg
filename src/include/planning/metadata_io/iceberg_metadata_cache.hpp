#pragma once

#include "duckdb/storage/object_cache.hpp"
#include "core/metadata/manifest/iceberg_manifest_list.hpp"
#include "core/metadata/iceberg_table_metadata.hpp"
#include "iceberg_options.hpp"
#include "planning/snapshot/iceberg_snapshot_scan_info.hpp"

namespace duckdb {

idx_t EstimateCacheMemory(const IcebergTableMetadata &metadata);
idx_t EstimateCacheMemory(const vector<IcebergManifestListEntry> &manifests);
idx_t EstimateCacheMemory(const vector<IcebergManifestEntry> &entries);

template <class VALUE>
class IcebergCacheEntry final : public ObjectCacheEntry {
public:
	IcebergCacheEntry(string version_p, VALUE value_p)
	    : version(std::move(version_p)), value(std::move(value_p)),
	      estimated_memory(sizeof(IcebergCacheEntry) + version.capacity() + EstimateCacheMemory(value)) {
	}

public:
	static string ObjectType();
	string GetObjectType() override {
		return ObjectType();
	}
	optional_idx GetEstimatedCacheMemory() const override {
		return estimated_memory;
	}

public:
	const string version;
	const VALUE value;

private:
	idx_t estimated_memory;
};

using IcebergTableMetadataCacheEntry = IcebergCacheEntry<IcebergTableMetadata>;
using IcebergManifestListCacheEntry = IcebergCacheEntry<vector<IcebergManifestListEntry>>;
using IcebergManifestCacheEntry = IcebergCacheEntry<vector<IcebergManifestEntry>>;

template <>
string IcebergTableMetadataCacheEntry::ObjectType();
template <>
string IcebergManifestListCacheEntry::ObjectType();
template <>
string IcebergManifestCacheEntry::ObjectType();

string IcebergMetadataFileVersion(FileSystem &fs, const string &path);

class IcebergManifestCache {
public:
	IcebergManifestCache(ClientContext &context, const IcebergOptions &options, const string &iceberg_path,
	                     const IcebergSnapshotScanInfo &snapshot_info, const IcebergTableMetadata &metadata,
	                     vector<IcebergManifestListEntry> &manifests);

public:
	bool Fill(idx_t idx) const;
	void Store(const vector<idx_t> &indexes) const;

private:
	string Key(const IcebergManifestFile &manifest) const;

private:
	ObjectCache &cache;
	vector<IcebergManifestListEntry> &manifests;
	string prefix;
	string decoding;
};

} // namespace duckdb

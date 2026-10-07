#include "planning/metadata_io/iceberg_metadata_cache.hpp"

#include "duckdb/common/file_system.hpp"

namespace duckdb {

namespace {

constexpr idx_t MAP_NODE_SIZE = 64;
constexpr idx_t VALUE_NODE_SIZE = 160;
constexpr idx_t SNAPSHOT_SIZE = 1280;
constexpr idx_t METADATA_LOG_ITEM_SIZE = 192;
constexpr idx_t COLUMN_SIZE = 256;
constexpr idx_t TABLE_DEFINITION_SIZE = 16384;

idx_t BlobMemory(const Value &value) {
	return value.IsNull() ? 0 : StringValue::Get(value).size();
}

idx_t BoundsMemory(const unordered_map<int32_t, Value> &bounds) {
	idx_t result = VALUE_NODE_SIZE * bounds.size();
	for (auto &bound : bounds) {
		result += BlobMemory(bound.second);
	}
	return result;
}

idx_t EntryMemory(const IcebergManifestEntry &entry) {
	auto &file = entry.data_file;
	idx_t result = sizeof(IcebergManifestEntry) + file.file_path.capacity() + file.file_format.capacity() +
	               (file.referenced_data_file ? file.referenced_data_file->capacity() : 0);
	result += file.partition_info.capacity() * sizeof(IcebergPartitionInfo);
	result += MAP_NODE_SIZE * (file.column_sizes.size() + file.value_counts.size() + file.null_value_counts.size() +
	                           file.nan_value_counts.size());
	result += BoundsMemory(file.lower_bounds) + BoundsMemory(file.upper_bounds);
	result += file.equality_ids.capacity() * sizeof(int32_t) + file.split_offsets.capacity() * sizeof(int64_t);
	return result;
}

string DecodingKey(const IcebergSnapshotScanInfo &snapshot_info, const IcebergTableMetadata &metadata,
                   const vector<IcebergManifestListEntry> &manifests) {
	auto result = std::to_string(metadata.iceberg_version);
	unordered_set<int32_t> partition_spec_ids;
	for (auto &manifest : manifests) {
		partition_spec_ids.insert(manifest.file.partition_spec_id);
	}
	if (partition_spec_ids.empty()) {
		return result;
	}
	auto field_types = IcebergDataFile::GetFieldIdToTypeMapping(snapshot_info, metadata, partition_spec_ids);
	for (auto &field_type : field_types) {
		idx_t specs = 0;
		for (auto &id_spec : metadata.partition_specs) {
			for (auto &field : id_spec.second.GetFields()) {
				if (field.partition_field_id == field_type.first) {
					specs++;
				}
			}
		}
		result +=
		    "|" + std::to_string(field_type.first) + ":" + field_type.second.ToString() + ":" + std::to_string(specs);
	}
	return result;
}

} // namespace

idx_t EstimateCacheMemory(const IcebergTableMetadata &metadata) {
	idx_t result = TABLE_DEFINITION_SIZE + metadata.snapshots.size() * SNAPSHOT_SIZE +
	               metadata.metadata_log.size() * METADATA_LOG_ITEM_SIZE +
	               metadata.snapshot_log.size() * 2 * sizeof(int64_t);
	metadata.GetSchemas().ForEachSchema(
	    [&result](const IcebergTableSchema &schema) { result += schema.columns.size() * COLUMN_SIZE; });
	return result;
}

idx_t EstimateCacheMemory(const vector<IcebergManifestListEntry> &manifests) {
	idx_t result = 0;
	for (auto &manifest : manifests) {
		result += sizeof(IcebergManifestListEntry) + manifest.file.manifest_path.capacity();
		for (auto &field : manifest.file.partitions.field_summary) {
			result += sizeof(FieldSummary) + BlobMemory(field.lower_bound) + BlobMemory(field.upper_bound);
		}
	}
	return result;
}

idx_t EstimateCacheMemory(const vector<IcebergManifestEntry> &entries) {
	idx_t result = 0;
	for (auto &entry : entries) {
		result += EntryMemory(entry);
	}
	return result;
}

string IcebergMetadataFileVersion(FileSystem &fs, const string &path) {
	auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
	return path + "|" + std::to_string(fs.GetFileSize(*handle)) + "|" +
	       std::to_string(fs.GetLastModifiedTime(*handle).value);
}

template <>
string IcebergTableMetadataCacheEntry::ObjectType() {
	return "iceberg_table_metadata";
}

template <>
string IcebergManifestListCacheEntry::ObjectType() {
	return "iceberg_manifest_list";
}

template <>
string IcebergManifestCacheEntry::ObjectType() {
	return "iceberg_manifest_entries";
}

IcebergManifestCache::IcebergManifestCache(ClientContext &context, const IcebergOptions &options,
                                           const string &iceberg_path, const IcebergSnapshotScanInfo &snapshot_info,
                                           const IcebergTableMetadata &metadata,
                                           vector<IcebergManifestListEntry> &manifests)
    : cache(ObjectCache::GetObjectCache(context)), manifests(manifests),
      prefix(options.allow_moved_paths ? iceberg_path + "|" : "|"),
      decoding("|" + DecodingKey(snapshot_info, metadata, manifests)) {
}

string IcebergManifestCache::Key(const IcebergManifestFile &manifest) const {
	return prefix + manifest.manifest_path + "|" + std::to_string(manifest.manifest_length) + decoding;
}

bool IcebergManifestCache::Fill(idx_t idx) const {
	auto &manifest = manifests[idx];
	auto cached = cache.GetWithTypePrefix<IcebergManifestCacheEntry>(Key(manifest.file));
	if (!cached) {
		return false;
	}
	manifest.manifest_entries = cached->value;
	return true;
}

void IcebergManifestCache::Store(const vector<idx_t> &indexes) const {
	for (auto idx : indexes) {
		auto &manifest = manifests[idx];
		if (!manifest.HasManifestEntries()) {
			continue;
		}
		cache.PutWithTypePrefix<IcebergManifestCacheEntry>(
		    Key(manifest.file), make_shared_ptr<IcebergManifestCacheEntry>(string(), manifest.GetManifestEntries()));
	}
}

} // namespace duckdb

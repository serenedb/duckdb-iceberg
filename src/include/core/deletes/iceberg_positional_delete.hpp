#pragma once

#include "duckdb/common/multi_file/multi_file_data.hpp"
#include "core/deletes/iceberg_delete_data.hpp"

namespace duckdb {

struct IcebergPositionalDeleteData : public enable_shared_from_this<IcebergPositionalDeleteData>, IcebergDeleteData {
public:
	IcebergPositionalDeleteData(const BoundIcebergManifestEntry &entry)
	    : IcebergDeleteData(IcebergDeleteType::POSITIONAL_DELETE, entry) {
	}
	virtual ~IcebergPositionalDeleteData() override {
	}

public:
	void AddRow(int64_t row_id) {
		invalid_rows.insert(row_id);
	}
	//! SereneDB fork: same row, tagged with its delete file's sequence number --
	//! REINDEX masks only rows from delete files NEWER than its manifest entry.
	void AddRow(int64_t row_id, sequence_number_t sequence_number) {
		if (rows_by_sequence.empty() || rows_by_sequence.back().first != sequence_number) {
			rows_by_sequence.emplace_back(sequence_number, vector<int64_t>());
		}
		rows_by_sequence.back().second.push_back(row_id);
		invalid_rows.insert(row_id);
	}
	unique_ptr<DeleteFilter> ToFilter() const override;
	void ToSet(set<idx_t> &out) const override;

public:
	//! Store invalid rows here before finalizing into a SelectionVector
	unordered_set<int64_t> invalid_rows;
	//! SereneDB fork: insertion-ordered (sequence number, rows) buckets --
	//! consecutive same-sequence delete files share a bucket.
	vector<pair<sequence_number_t, vector<int64_t>>> rows_by_sequence;
};

struct IcebergPositionalDeleteFilter : public DeleteFilter {
public:
	IcebergPositionalDeleteFilter(shared_ptr<const IcebergPositionalDeleteData> data) : data(data) {
	}

public:
	idx_t Filter(row_t start_row_index, idx_t count, SelectionVector &result_sel) override {
		if (count == 0) {
			return 0;
		}
		result_sel.Initialize(STANDARD_VECTOR_SIZE);
		idx_t selection_idx = 0;
		auto &invalid_rows = data->invalid_rows;
		for (idx_t i = 0; i < count; i++) {
			if (!invalid_rows.count(i + start_row_index)) {
				result_sel.set_index(selection_idx++, i);
			}
		}
		return selection_idx;
	}

public:
	//! Immutable state of the positional delete
	shared_ptr<const IcebergPositionalDeleteData> data;
};

} // namespace duckdb

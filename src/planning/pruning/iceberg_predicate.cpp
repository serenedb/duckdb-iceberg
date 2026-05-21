#include "planning/pruning/iceberg_predicate.hpp"

#include "duckdb/planner/expression/bound_comparison_expression.hpp"
#include "duckdb/planner/expression/bound_conjunction_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression/bound_operator_expression.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/planner/filter/expression_filter.hpp"
#include "duckdb/planner/filter/table_filter_functions.hpp"
#include "duckdb/planner/logical_operator_visitor.hpp"
#include "duckdb/execution/expression_executor.hpp"

namespace duckdb {

namespace {

struct BoundExpressionReplacer : public LogicalOperatorVisitor {
public:
	BoundExpressionReplacer(const Value &val) : val(val) {
	}

public:
	unique_ptr<Expression> VisitReplace(BoundReferenceExpression &expr, unique_ptr<Expression> *expr_ptr) override {
		if (expr.index != 0) {
			return nullptr;
		}
		auto &return_type = expr.GetReturnType();
		return make_uniq<BoundConstantExpression>(val.DefaultCastAs(return_type, true));
	}

public:
	const Value &val;
};

} // namespace

template <class TRANSFORM>
bool MatchBoundsTemplated(ClientContext &context, const ExpressionFilter &filter, const IcebergPredicateStats &stats,
                          const IcebergTransform &transform);

template <class TRANSFORM>
static bool MatchBoundsConstant(const Value &constant, ExpressionType comparison_type,
                                const IcebergPredicateStats &stats, const IcebergTransform &transform) {
	auto constant_value = TRANSFORM::ApplyTransform(constant, transform);

	if (stats.BoundsAreNull()) {
		// bounds are actually null, expression is not a null comparison expression
		// those are handled in MatchBoundsTemplated
		// So we can return false since no remaining expression type will match a null value
		D_ASSERT(comparison_type != ExpressionType::OPERATOR_IS_NOT_NULL);
		D_ASSERT(comparison_type != ExpressionType::OPERATOR_IS_NULL);
		D_ASSERT(comparison_type != ExpressionType::COMPARE_DISTINCT_FROM);
		D_ASSERT(comparison_type != ExpressionType::COMPARE_NOT_DISTINCT_FROM);
		return false;
	}

	if (!stats.has_upper_bounds || !stats.has_lower_bounds) {
		// we do not have upper or lower bounds, assume the file matches.
		return true;
	}

	switch (comparison_type) {
	case ExpressionType::COMPARE_EQUAL:
		return TRANSFORM::CompareEqual(constant_value, stats);
	case ExpressionType::COMPARE_GREATERTHAN:
		return TRANSFORM::CompareGreaterThan(constant_value, stats);
	case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
		return TRANSFORM::CompareGreaterThanOrEqual(constant_value, stats);
	case ExpressionType::COMPARE_LESSTHAN:
		return TRANSFORM::CompareLessThan(constant_value, stats);
	case ExpressionType::COMPARE_LESSTHANOREQUALTO:
		return TRANSFORM::CompareLessThanOrEqual(constant_value, stats);
	default:
		//! Conservative approach: we don't know, so we just say it's not filtered out
		return true;
	}
}

template <class TRANSFORM>
static bool MatchBoundsIsNullFilter(const IcebergPredicateStats &stats, const IcebergTransform &transform) {
	return stats.has_null == true;
}

template <class TRANSFORM>
static bool MatchBoundsIsNotNullFilter(const IcebergPredicateStats &stats, const IcebergTransform &transform) {
	return stats.has_not_null == true;
}

static bool IsDirectReference(const Expression &expr) {
	switch (expr.GetExpressionClass()) {
	case ExpressionClass::BOUND_REF:
	case ExpressionClass::BOUND_COLUMN_REF:
		return true;
	default:
		return false;
	}
}

template <class TRANSFORM>
bool MatchTransformedBounds(ClientContext &context, ExpressionType comparison_type, const Expression &left,
                            const Expression &right, const IcebergPredicateStats &stats,
                            const IcebergTransform &transform) {
	BoundExpressionReplacer lower_replacer(stats.lower_bound);
	BoundExpressionReplacer upper_replacer(stats.upper_bound);
	auto lower_copy = left.Copy();
	auto upper_copy = left.Copy();
	lower_replacer.VisitExpression(&lower_copy);
	upper_replacer.VisitExpression(&upper_copy);

	Value right_constant;
	if (!ExpressionExecutor::TryEvaluateScalar(context, right, right_constant)) {
		return true;
	}

	Value transformed_lower_bound;
	Value transformed_upper_bound;
	if (!ExpressionExecutor::TryEvaluateScalar(context, *lower_copy, transformed_lower_bound)) {
		return true;
	}
	if (!ExpressionExecutor::TryEvaluateScalar(context, *upper_copy, transformed_upper_bound)) {
		return true;
	}
	IcebergPredicateStats transformed_stats(stats);
	transformed_stats.lower_bound = transformed_lower_bound;
	transformed_stats.upper_bound = transformed_upper_bound;

	return MatchBoundsConstant<TRANSFORM>(right_constant, comparison_type, transformed_stats, transform);
}

template <class TRANSFORM>
static bool MatchBoundsExpression(ClientContext &context, const Expression &expr, const IcebergPredicateStats &stats,
                                  const IcebergTransform &transform) {
	if (BoundComparisonExpression::IsComparison(expr)) {
		// ExpressionFilter on strings (e.g. len(my_string_col)) does not maintain lexicographic
		// ordering properties — be conservative and accept the row group.
		if (stats.lower_bound.type() == LogicalType::VARCHAR) {
			return true;
		}
		auto &compare_expr = expr.Cast<BoundFunctionExpression>();
		auto comparison_type = compare_expr.GetExpressionType();
		auto &left = BoundComparisonExpression::Left(compare_expr);
		auto &right = BoundComparisonExpression::Right(compare_expr);
		if (IsDirectReference(left) && right.GetExpressionClass() == ExpressionClass::BOUND_CONSTANT) {
			return MatchBoundsConstant<TRANSFORM>(right.Cast<BoundConstantExpression>().value, comparison_type, stats,
			                                      transform);
		}
		if (left.GetExpressionClass() == ExpressionClass::BOUND_CONSTANT && IsDirectReference(right)) {
			return MatchBoundsConstant<TRANSFORM>(left.Cast<BoundConstantExpression>().value,
			                                      FlipComparisonExpression(comparison_type), stats, transform);
		}
		if (transform.Type() == IcebergTransformType::IDENTITY) {
			//! No further processing has been done on the stats (lower/upper bounds)
			bool left_foldable = left.IsFoldable();
			bool right_foldable = right.IsFoldable();
			if (!left_foldable && !right_foldable) {
				//! Both are not foldable, can't evaluate at all
				return true;
			}
			if (left_foldable) {
				return MatchTransformedBounds<TRANSFORM>(context, comparison_type, right, left, stats, transform);
			}
			return MatchTransformedBounds<TRANSFORM>(context, comparison_type, left, right, stats, transform);
		}
		return true;
	}

	switch (expr.GetExpressionClass()) {
	case ExpressionClass::BOUND_CONJUNCTION: {
		auto &conjunction = expr.Cast<BoundConjunctionExpression>();
		if (conjunction.GetExpressionType() != ExpressionType::CONJUNCTION_AND) {
			return true;
		}
		for (auto &child : conjunction.children) {
			if (!MatchBoundsExpression<TRANSFORM>(context, *child, stats, transform)) {
				return false;
			}
		}
		return true;
	}
	case ExpressionClass::BOUND_OPERATOR: {
		auto &bound_operator_expr = expr.Cast<BoundOperatorExpression>();
		switch (expr.GetExpressionType()) {
		case ExpressionType::OPERATOR_IS_NULL:
		case ExpressionType::OPERATOR_IS_NOT_NULL: {
			//! Expressions can be arbitrarily complex, and we currently only support IS NULL/IS NOT NULL checks against
			//! the column itself, i.e. where the expression is a BOUND_OPERATOR with type OPERATOR_IS_NULL/_IS_NOT_NULL
			//! with a single child expression of type BOUND_REF.
			//!
			//! See duckdb/duckdb-iceberg#464
			if (bound_operator_expr.children.size() != 1 || !IsDirectReference(*bound_operator_expr.children[0])) {
				//! We can't evaluate expressions that aren't direct column references
				return true;
			}
			if (expr.GetExpressionType() == ExpressionType::OPERATOR_IS_NULL) {
				return MatchBoundsIsNullFilter<TRANSFORM>(stats, transform);
			}
			D_ASSERT(expr.GetExpressionType() == ExpressionType::OPERATOR_IS_NOT_NULL);
			return MatchBoundsIsNotNullFilter<TRANSFORM>(stats, transform);
		}
		case ExpressionType::COMPARE_IN: {
			if (bound_operator_expr.children.empty() || !IsDirectReference(*bound_operator_expr.children[0])) {
				return true;
			}
			for (idx_t i = 1; i < bound_operator_expr.children.size(); i++) {
				if (bound_operator_expr.children[i]->GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
					return true;
				}
				auto &value = bound_operator_expr.children[i]->Cast<BoundConstantExpression>().value;
				if (MatchBoundsConstant<TRANSFORM>(value, ExpressionType::COMPARE_EQUAL, stats, transform)) {
					return true;
				}
			}
			return false;
		}
		default:
			return true;
		}
	}
	case ExpressionClass::BOUND_FUNCTION: {
		auto &func = expr.Cast<BoundFunctionExpression>();
		if (func.function.GetName() == OptionalFilterScalarFun::NAME && func.bind_info) {
			auto &data = func.bind_info->Cast<OptionalFilterFunctionData>();
			if (data.child_filter_expr) {
				return MatchBoundsExpression<TRANSFORM>(context, *data.child_filter_expr, stats, transform);
			}
			//! child filter wasn't populated (yet?) for some reason, just be conservative
			return true;
		}
		if (func.function.GetName() == SelectivityOptionalFilterScalarFun::NAME && func.bind_info) {
			auto &data = func.bind_info->Cast<SelectivityOptionalFilterFunctionData>();
			if (data.child_filter_expr) {
				return MatchBoundsExpression<TRANSFORM>(context, *data.child_filter_expr, stats, transform);
			}
			//! child filter wasn't populated (yet?) for some reason, just be conservative
			return true;
		}
		return true;
	}
	default:
		//! Conservative approach: we don't know what this is, just say it doesn't filter anything
		return true;
	}
}

template <class TRANSFORM>
bool MatchBoundsTemplated(ClientContext &context, const ExpressionFilter &filter, const IcebergPredicateStats &stats,
                          const IcebergTransform &transform) {
	return MatchBoundsExpression<TRANSFORM>(context, *filter.expr, stats, transform);
}

bool IcebergPredicate::MatchBounds(ClientContext &context, const ExpressionFilter &filter,
                                   const IcebergPredicateStats &stats, const IcebergTransform &transform) {
	switch (transform.Type()) {
	case IcebergTransformType::IDENTITY:
		return MatchBoundsTemplated<IdentityTransform>(context, filter, stats, transform);
	case IcebergTransformType::BUCKET:
		return MatchBoundsTemplated<BucketTransform>(context, filter, stats, transform);
	case IcebergTransformType::TRUNCATE:
		return MatchBoundsTemplated<TruncateTransform>(context, filter, stats, transform);
	case IcebergTransformType::YEAR:
		return MatchBoundsTemplated<YearTransform>(context, filter, stats, transform);
	case IcebergTransformType::MONTH:
		return MatchBoundsTemplated<MonthTransform>(context, filter, stats, transform);
	case IcebergTransformType::DAY:
		return MatchBoundsTemplated<DayTransform>(context, filter, stats, transform);
	case IcebergTransformType::HOUR:
		return MatchBoundsTemplated<HourTransform>(context, filter, stats, transform);
	case IcebergTransformType::VOID:
		return true;
	default:
		throw InvalidConfigurationException("Transform '%s' not implemented", transform.RawType());
	}
}

} // namespace duckdb

#include <vector>
#include <random>
#include <iostream>
#include "common.h"
#include "log.h"
using namespace std;

class Client {
private:
	const size_t id_;
	const GroupInfo group_info_;
	ParamType param_;

    SecaggConfig config_;

	ParamType Syt_ = ParamType(0);
	PolynomialType Fn_;

	static constexpr size_t MSG_BUFF_SIZE = 1024;
	char msg_buf_[MSG_BUFF_SIZE];

	vector<ParamType> _get_random_coefficients() const {
		vector<ParamType> coefficients(config_.n_corrupted+1);
		coefficients[0] = param_;
		for (size_t i = 1; i<coefficients.size(); ++i) {
			coefficients[i] = ParamType::random();
		}
		return coefficients;
	}

public:
	Client(size_t id, const ParamType &param, const SecaggConfig &config) :
	id_(id), param_(param), group_info_(id, config), Fn_(_get_random_coefficients()), config_(config) {}

	ParamType get_coded_params_to_group_member(size_t id_in_group) const {
		assert(id_in_group < config_.group_size);
		return Fn_(at(id_in_group));
	}

	void set_coded_params_from_group_member(size_t id_in_group, const ParamType &param) {
		assert(id_in_group < config_.group_size);
		Syt_ = Syt_ + param;
	}

	void set_aggregated_param_from_prev_group_member(const ParamType &param) {
		Syt_ = Syt_ + param;
	}

	ParamType get_aggregated_param_to_next_group_member() {
		assert(group_info_.group < config_.n_group - 1);
		return Syt_;
	}

	ParamType get_local_aggregation_to_server() {
		assert(group_info_.group == config_.n_group - 1);
		return Syt_;
	}

	size_t client_id() const { return id_; }
	const GroupInfo &group_info() const { return group_info_; }
	size_t group() const { return group_info().group; }
	size_t id_in_group() const { return group_info().id_in_group; }
	const ParamType &param() const { return param_; }

    const PolynomialType &get_random_polynomial_for_test() { return Fn_; }
};

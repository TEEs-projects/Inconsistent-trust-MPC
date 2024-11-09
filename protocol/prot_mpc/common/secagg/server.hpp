#include <utility>
#include <memory>
#include "common.h"
#include "log.h"
#include "interpolation.hpp"
using namespace std;

class Server {
private:
	vector<pair<FieldType, ParamType>> points_;

	static constexpr size_t MSG_BUFF_SIZE = 1024;
	char msg_buf_[MSG_BUFF_SIZE];

    SecaggConfig config_;

	ParamType _recover(const vector<pair<FieldType, ParamType>> &points) {
#ifndef NDEBUG
#ifndef NDEBUG_AGG_SERVER
		cout << "Received points: " << endl;
		for (const auto &point : points) {
			cout << "x: " << point.first << ", y: " << point.second << endl;
		}
#endif
#endif
		return LagrangeInterpolation<FieldType, ParamType>::interpolate_at(points, 0);
	}

public:
	explicit Server(const SecaggConfig &config) : config_(config) { points_.reserve(config.group_size); }

	void set_aggregation_from_client(size_t id_in_group, const ParamType &param) {
		points_.emplace_back(at(id_in_group), param);
	}

	ParamType aggregate() {
		return _recover(points_);
	}
};

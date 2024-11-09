#pragma once
#include <vector>
#include <utility>

template<typename X, typename Y>
struct LagrangeInterpolation {
	// O(n^2) plain implementation
	static Y interpolate_at(const std::vector<std::pair<X, Y>> &points, const X &x) {
		Y res(0);
		for (size_t i = 0; i<points.size(); ++i) {
			X numerator(1);
			X denominator(1);
			for (size_t j = 0; j<i; ++j) {
				denominator = denominator * (points[i].first - points[j].first);
				numerator = numerator * (x - points[j].first);
			}
			for (size_t j = i+1; j<points.size(); ++j) {
				denominator = denominator * (points[i].first - points[j].first);
				numerator = numerator * (x - points[j].first);
			}
			res = res + numerator / denominator * points[i].second;
		}
		return res;
	}
};

#pragma once
#include <vector>
#include <iostream>

template<typename X, typename Y>
class Polynomial {
private:
	std::vector<Y> coefficients_;

public:
	Polynomial(const std::vector<Y> &coefficients) :
		coefficients_(coefficients) { assert(coefficients.size() > 0); }

	Y operator()(const X &e) const {
		Y res(coefficients_[0]);
		X x = e;
		for (size_t i = 1; i<coefficients_.size(); ++i) {
			res = res + coefficients_[i] * x;
			x = x*e;
		}
		return res;
	}

	const std::vector<Y> &coefficients() const { return coefficients_; }
};

template<typename X, typename Y>
std::ostream &operator<<(std::ostream &os, const Polynomial<X, Y> &polynomial) {
	const std::vector<Y> &coefficients = polynomial.coefficients();
	assert(coefficients.size() > 0);
	os << coefficients[0];
	for (size_t i = 1; i<coefficients.size(); ++i) {
		os << " + ";
		os << coefficients[i]  << "x^" << i << " ";
	}
	return os;
}

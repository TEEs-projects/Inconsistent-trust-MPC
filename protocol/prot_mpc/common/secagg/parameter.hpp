#pragma once
#include <iostream>
#include <vector>
#include <array>

template<typename Field, size_t l>
class Parameter {
private:
	std::array<Field, l> val_;

public:
	Parameter() {}
	Parameter(const Field &f) { val_.fill(f); }
	Parameter(const std::array<Field, l> &val) : val_(val) {}

	Parameter operator*(const Field &c) const {
		Parameter res;
		for (size_t i = 0; i<val_.size(); ++i) {
			res.val_[i] = val_[i] * c;
		}
		return res;
	}

	Parameter operator+(const Parameter &rhs) const {
		Parameter res;
		for (size_t i = 0; i<val_.size(); ++i) {
			res.val_[i] = this->val_[i] + rhs.val_[i];
		}
		return res;
	}

	Parameter operator-(const Parameter &rhs) const {
		Parameter res;
		for (size_t i = 0; i<val_.size(); ++i) {
			res.val_[i] = this->val_[i] - rhs.val_[i];
		}
		return res;
	}

	bool operator==(const Parameter &rhs) const { return val_ == rhs.val_; }

	const std::array<Field, l> &val() const { return val_; }

	static Parameter random() {
		std::array<Field, l> ret;
		for (auto &x : ret) {
			x = Field::random();
		}
		return ret;
	}

    void to_bytes(uint8_t *buf) const {
        for (size_t i=0; i<l; ++i) {
            val_[i].to_bytes(buf);
            buf += Field::size();
        }
    }

    static Parameter from_bytes(const uint8_t *buf) {
        std::array<Field, l> val;
        for (size_t i=0; i<l; ++i) {
            val[i] = Field::from_bytes(buf);
            buf += Field::size();
        }
        return Parameter(val);
    }

    static constexpr size_t size() { return sizeof(Num) * l; }
};

template<typename Field, size_t l>
Parameter<Field, l> operator*(const Field &f, const Parameter<Field, l> &param) {
	return param * f;
}

template<typename Field, size_t l>
std::ostream &operator<<(std::ostream &os, const Parameter<Field, l> &param) {
	const auto &val = param.val();
	assert(val.size() > 0);
	os << "(" << val[0];
	for (size_t i = 1; i<val.size(); ++i) {
		os << ", " << val[i];
	}
	os << ")";
	return os;
}

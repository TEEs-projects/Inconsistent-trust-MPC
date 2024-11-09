#pragma once
#include <iostream>
#include <cassert>
#include <random>

using Num = unsigned long long;

template<Num p>
class Zp {
private:
	Num x_;
	static std::random_device rd; // TODO: use CSPRNG instead of std library to generate random Zp elements
	static std::mt19937_64 mt;
	static std::uniform_int_distribution<Num> distrb;

// au = 1 (mod b)
	static void _exgcd(Num a, Num b, Num &d, Num &u, Num &v) {
		if (b == 0) {
			d = a;
			u = 1;
			v = 0;
			return;
		}
		_exgcd(b, a%b, d, v, u);
		v -= a/b*u;
	}

	static Num _inv(Num a) {
		Num d, u, v;
		_exgcd(a, p, d, u, v);
		return d == 1 ? (u + p)%p : -1;
	}

public:
	Zp() : x_(0) {}
	Zp(Num x) : x_(x) { assert(x >= 0 && x < p); }

	Zp inv() { return _inv(x_); }

	Zp operator+(Zp rhs) const { return (x_ + rhs.x_) % p; }
	Zp operator-(Zp rhs) const { return (p + x_ - rhs.x_) % p; }
	Zp operator*(Zp rhs) const { return (x_ * rhs.x_) % p; }
	Zp operator/(Zp rhs) const { return *this * rhs.inv(); }
	bool operator==(Zp rhs) const { return x_ == rhs.x_; }

	Num val() const { return x_; }

	static Zp random() {
		Num r = distrb(mt);
		return Zp(r);
	}

    void to_bytes(uint8_t *buf) const {
        // little endian
        Num x = x_;
        for (uint8_t *cur = buf; cur != buf+sizeof(Num); ++cur) {
            *cur = x & 0xff;
            x >>= 8;
        }
    }

    static Zp from_bytes(const uint8_t *buf) {
        Num x = 0;
        for (const uint8_t *cur = buf+sizeof(Num)-1; cur != buf-1; --cur) {
            x <<= 8;
            x |= *cur;
        }
        return Zp(x);
    }

    static constexpr size_t size() { return sizeof(Num); }
};

template<Num p>
std::random_device Zp<p>::rd;

template<Num p>
std::mt19937_64 Zp<p>::mt(rd());

template<Num p>
std::uniform_int_distribution<Num> Zp<p>::distrb(0, p-1);

template<Num p>
std::ostream &operator<<(std::ostream &os, const Zp<p> &zp) {
	return os << zp.val();
}

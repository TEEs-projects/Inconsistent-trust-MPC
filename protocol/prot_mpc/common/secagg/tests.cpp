#include <iostream>
#include <vector>
#include <random>
#include <array>
#include <cassert>
#include <ctime>
#include "zp.hpp"
#include "parameter.hpp"
#include "polynomial.hpp"
#include "interpolation.hpp"
#include "client.hpp"
#include "server.hpp"
using namespace std;

void test_polynomial() {
	cout << "Testing polynomial..." << endl;
	Parameter<Zp<3>, 1> zp3_0(Zp<3>(0));
	Parameter<Zp<3>, 1> zp3_1(Zp<3>(1));
	Parameter<Zp<3>, 1> zp3_2(Zp<3>(2));
	// P(x) = 1 + 2x + x^2
	Polynomial<Zp<3>, Parameter<Zp<3>, 1>> poly(vector<Parameter<Zp<3>, 1>>{zp3_1, zp3_2, zp3_1});
	
	cout << poly(Zp<3>(0)) << endl;
}

void test_parameter() {
	cout << "Testing parameter..." << endl;
	Parameter<Zp<11>, 7> param1(array<Zp<11>, 7>{1, 2, 3, 4, 5, 6, 7});
	Parameter<Zp<11>, 7> param2(array<Zp<11>, 7>{2, 3, 4, 6, 7, 9, 10});
	Zp<11> c(2);
	auto res1 = param1 * c;
	auto res2 = param1 + param2;
	cout << res1 << endl;
	cout << res2 << endl;

	const size_t N = 10;
	for (size_t i = 0; i<N; ++i) {
		auto r = Parameter<Zp<11>, 7>::random();
		cout << r << endl;
	}

	cout << endl;
}

void test_zp() {
	cout << "Testing zp..." << endl;
	Zp<11> x(5), y(3);

	cout << "x: " << x.val() << " y: " << y.val() << endl;
	cout << "x+y: " << (x+y).val() << endl;
	cout << "x-y: " << (x-y).val() << endl;
	cout << "x*y: " << (x*y).val() << endl;
	cout << "x/y: " << (x/y).val() << endl;

	const size_t N = 10;
	for (size_t i = 0; i<N; ++i) {
		cout << Zp<11>::random().val() << " ";
	}
	cout << endl;

	for (size_t i = 0; i<N; ++i) {
		cout << Zp<2>::random().val() << " ";
	}
	cout << endl;
}

void test_lagrange() {
	cout << "Testing lagrange..." << endl;

	constexpr Num P = 5;
	// p(x) = 2 + 3x
	Polynomial<Zp<P>, Parameter<Zp<P>, 3>> p(
		vector<Parameter<Zp<P>, 3>>{ 
			Parameter<Zp<P>, 3>({3, 3, 2}), Parameter<Zp<P>, 3>({2, 3, 3}), Parameter<Zp<P>, 3>({1, 2, 3}) 
		}
	);

	vector<pair<Zp<P>, Parameter<Zp<P>, 3>>> points;
	vector<Zp<P>> xs{ 1, 2, 3 };
	for (auto x : xs) {
		points.emplace_back(x, p(x));
	}

	for (Num i = 0; i<P; ++i) {
		Zp<P> x(i);
		using Interp = LagrangeInterpolation<Zp<P>, Parameter<Zp<P>, 3>>;
		cout << i << " " << Interp::interpolate_at(points, x) << " " << p(x) << endl;
		//assert(Interp::interpolate_at(points, x) == p(x));
	}
}

void test_client() {
	cout << "Testing client..." << endl;
	vector<Client> clients;
	for (size_t i = 0; i<N_CLIENT; ++i) {
		ParamType param = ParamType::random();
		clients.push_back(Client(i, param));
		cout << param << endl;
	}
	ParamType sum(0);
	for (size_t i = 0; i<N_CLIENT; ++i) {
		sum = sum + clients[i].param();
	}
	cout << sum << endl;
}

void test_server() {
	Server server;
	server.aggregate();
}

void test_secagg() {
	cout << "Testing secagg..." << endl;
	vector<Client> clients;
	Server server;

	ParamType sum;
	for (size_t i = 0; i<N_CLIENT; ++i) {
		ParamType param = ParamType::random();
		sum = sum + param;
		cout << "Parameters of client " << i << " : " << param << endl;
		Client client(i, param);
		cout << "Group: " << client.group() << ", ID in group: " << client.id_in_group() << endl;
		cout << "Client ID: " << GroupInfo::to_client_id(client.group_info()) << endl;
		clients.emplace_back(client);
	}

	time_t t1 = clock();
	for (size_t i = 0; i<N_GROUP; ++i) {
		for (size_t j = 0; j<GROUP_SIZE; ++j) {
			GroupInfo info_x(i, j);
			Client &x = clients[GroupInfo::to_client_id(info_x)];
			for (size_t k = 0; k<GROUP_SIZE; ++k) {
				GroupInfo info_y(i, k);
				Client &y = clients[GroupInfo::to_client_id(info_y)];
				ParamType p_x = x.get_coded_params_to_group_member(k);
				y.set_coded_params_from_group_member(j, p_x);
			}
			if (i > 0) {
				size_t prev_member_id = GroupInfo::to_client_id(x.group_info().prev_group_member_info());
				Client &y = clients[prev_member_id];
				ParamType p_y = y.get_aggregated_param_to_next_group_member();
				x.set_aggregated_param_from_prev_group_member(p_y);
			}
		}
	}
	for (size_t id_in_group = 0; id_in_group<GROUP_SIZE; ++id_in_group) {
		Client &c = clients[GroupInfo::to_client_id(GroupInfo(N_GROUP-1, id_in_group))];
		server.set_aggregation_from_client(id_in_group, c.get_local_aggregation_to_server());
	}
	time_t t2 = clock();

	time_t t3 = clock();
	auto res = server.aggregate();
	time_t t4 = clock();

	cout << "Aggregated parameter: " << res << endl;
	cout << "Sum of parameters: " << sum << endl;

	printf("Send coded params for %.2f seconds\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	printf("Server aggregate for %.2f seconds\n", (double)(t4-t3)/CLOCKS_PER_SEC);

}

int main() {
	test_zp();
	cout << endl;
	test_parameter();
	cout << endl;
	test_polynomial();
	cout << endl;

	test_lagrange();
	test_client();

	cout << endl;
	test_secagg();
}

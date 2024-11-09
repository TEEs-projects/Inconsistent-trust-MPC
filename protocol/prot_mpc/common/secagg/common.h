#pragma once
#include "zp.hpp"
#include "parameter.hpp"
#include "polynomial.hpp"
#include "check.h"
#include "types.h"

struct SecaggConfig {
    const size_t n_client;
    const size_t n_corrupted;
    const size_t n_drop;
    const size_t group_size;
    const size_t n_group;

    SecaggConfig(size_t n_client, size_t n_corrupted, size_t n_drop):
        n_client(n_client),
        n_corrupted(n_corrupted),
        n_drop(n_drop),
        group_size(n_corrupted + n_drop + 1),
        n_group(n_client / group_size)
    {
        check(n_client % group_size == 0);
    }

    explicit SecaggConfig(size_t n_client): SecaggConfig(n_client, n_client-1, 0) {}
};

struct GroupInfo {
private:
	static size_t _group(size_t client_id, size_t group_size) { return client_id / group_size; }
	static size_t _id_in_group(size_t client_id, size_t group_size) { return client_id % group_size; }

public:
	const size_t group;
	const size_t id_in_group;
    const SecaggConfig config;

	static GroupInfo to_group_info(size_t client_id, const SecaggConfig &config) { return GroupInfo(client_id, config); }
	static size_t to_client_id(const GroupInfo &info) { return info.group * info.config.group_size + info.id_in_group; }

	GroupInfo(size_t group, size_t id_in_group, const SecaggConfig &config):
        group(group),
        id_in_group(id_in_group),
        config(config) {}
    GroupInfo(size_t client_id, const SecaggConfig &config):
        GroupInfo(_group(client_id, config.group_size),
                  _id_in_group(client_id, config.group_size),
                  config) {}

	GroupInfo next_group_member_info() const {
		return GroupInfo(group+1, id_in_group, config);
	}

	GroupInfo prev_group_member_info() const {
		return GroupInfo(group-1, id_in_group, config);
	}

    GroupInfo group_member(size_t peer_id_in_group) const {
        return GroupInfo(group, peer_id_in_group, config);
    }
};

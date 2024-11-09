#pragma once

#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include <chrono>

#include <sys/types.h>
#include <sys/socket.h>
#include "asio.hpp"

#include <mbedtls/sha256.h>

#include <nlohmann/json.hpp>

#include "constant.h"

using namespace asio;
using namespace nlohmann;

struct ProtMPCConfig {
    size_t n_prot_mpc_client;

    std::vector<ip::address> client_ips;
    ip::address sgx_server_ip;
    ip::address amd_server_ip;

    static ProtMPCConfig load(const std::string &config_path) {
        std::ifstream f(config_path);
        check(static_cast<bool>(f));
        json json_config = json::parse(f);

        ProtMPCConfig config;
        config.sgx_server_ip = ip::address::from_string(
            json_config["server"]["sgx"]["ip"]
        );
        config.amd_server_ip = ip::address::from_string(
            json_config["server"]["amd"]["ip"]
        );
        config.n_prot_mpc_client = json_config["client"]["n_prot_mpc_client"];

        config.client_ips.reserve(config.n_prot_mpc_client);
        const auto &ip_strs = json_config["client"]["ip"];
        for (size_t i=0; i<ip_strs.size(); ++i) {
            config.client_ips.push_back(
                ip::address::from_string(ip_strs[i])
            );
        }
        while (config.client_ips.size() < config.n_prot_mpc_client) {
            config.client_ips.push_back(
                ip::address::from_string("127.0.0.1")
            );
        }

        check(config.n_prot_mpc_client <= MAX_N_PROT_MPC_CLIENT);

        return config;
    }
};

struct ProtMPCClientConfig {
    ProtMPCConfig prot_mpc_config;

    uint32_t client_id;

    static ProtMPCClientConfig load_with_id(const std::string &path, size_t id) {
        ProtMPCClientConfig config;
        config.prot_mpc_config = ProtMPCConfig::load(path);
        config.client_id = id;
        return config;
    }
};

static inline void print_binary(
    std::ostream &os,
    const uint8_t *buf,
    size_t buf_len
) {
    static const char digits[] = "0123456789ABCDEF";

    os << "0x";
    for (size_t i=0; i<buf_len; ++i) {
        os << digits[buf[i]>>4];
        os << digits[buf[i]&0xf];
    }
}

#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
using Time = decltype(std::chrono::high_resolution_clock::now());
using Duration = decltype(Time() - Time());
#endif

#ifdef NDEBUG
#define endl '\n'
#define fflush(stdout) (void)0
#endif

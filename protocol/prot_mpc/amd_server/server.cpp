// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <memory>
#include <future>
#include <mutex>
#include <iostream>
#include <fstream>
#include <thread>

#include <asio.hpp>

#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/rsa.h>
#include <mbedtls/cipher.h>
#include <mbedtls/error.h>

#include "constant.h"
#include "config.h"
#include "evidence/evidence_verifier.h"
#include "secagg/client.hpp"
#include "secagg/common.h"
#include "network.h"

using namespace std::chrono;
using namespace std;
using namespace asio;

struct Args {
    static ProtMPCConfig parse(int argc, char *argv[]) {
        check(argc >= 2);
        return ProtMPCConfig::load(argv[1]);
    }
};

class AMDServer {
private:
// TODO: recycle resources
    ProtMPCConfig config_;

    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    vector<char> input_received;

    io_context io;
    vector<unique_ptr<ip::tcp::socket>> client_conns;
    mutex mu_conn;
    unique_ptr<ip::tcp::socket> sgx_server_conn;

    CommitMessage commit_msg;

    static constexpr size_t MSG_BUF_SIZE = 1024 * 1024 * 24;
    const size_t PER_CLIENT_MSG_BUF_SIZE = 0;
    uint8_t *msg_buf = new uint8_t[MSG_BUF_SIZE];

    static constexpr size_t EVIDENCE_BUF_SIZE = 1024 * 1024 * 24;
    const size_t PER_CLIENT_EVIDENCE_BUF_SIZE = 0;
    uint8_t evidence_buf[EVIDENCE_BUF_SIZE];

    EID eid_bc;
    EID eid;

    EvidenceVerifier evidence_verifier;

    vector<mbedtls_cipher_context_t> symkey;

    unique_ptr<Client> client;
    ParamType secagg_input;

    mutex mu_inp;

#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
    Duration time_agg = Duration(0);
#endif

    void listen_and_connect() {
        cout << "Server: connect to SGX server" << endl;
        auto ep = ip::tcp::endpoint(config_.sgx_server_ip, SGX_SERVER_LISTEN_SERVER_PORT);
        sgx_server_conn.reset(new ip::tcp::socket(io));
        while (true) {
            try {
                sgx_server_conn->connect(ep);
                break;
            } catch (const std::exception &e) {
                this_thread::sleep_for(CONNECT_PERIOD);
            }
        }

        vector<future<void>> ft_conns;
        ft_conns.reserve(config_.n_prot_mpc_client);
        ip::tcp::acceptor client_acceptor(io, ip::tcp::endpoint(ip::tcp::v4(), AMD_SERVER_PORT));
        cout << "Server: listen to clients" << endl;

        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            unique_ptr<ip::tcp::socket> conn(new ip::tcp::socket(io));
            client_acceptor.accept(*conn);

            ft_conns.push_back(
                std::async(
                    [&](unique_ptr<ip::tcp::socket> conn) {
                        size_t client_id = confirm_client_id(conn);
                        check(client_id < config_.n_prot_mpc_client);

                        mu_conn.lock();
                        check(client_conns[client_id] == nullptr);
                        client_conns[client_id].reset(conn.release());
                        mu_conn.unlock();
#ifndef NDEBUG
                        cout << "Server: accept client connection with id " << client_id << endl;
#endif
                    },
                    std::move(conn)
                )
            );
        }
        for (auto &ft : ft_conns) {
            ft.get();
        }

        msg_buf[0] = MSG_OK;
        for (size_t client_id=0; client_id<config_.n_prot_mpc_client; ++client_id) {
            write(*client_conns[client_id], buffer(msg_buf, 1));
        }
    }

    void receive_commit_msg() {
        cout << "Server: receive commit message from SGX server" << endl;
        SignedMessage signed_msg = recv_signed_msg(
            sgx_server_conn,
            msg_buf,
            MSG_BUF_SIZE,
            evidence_buf,
            EVIDENCE_BUF_SIZE
        );

        bool ok = evidence_verifier.verify_evidence(
            &sgx_remote_uuid,
            signed_msg.sig,
            signed_msg.sig_len,
            signed_msg.msg,
            signed_msg.msg_len
        );
        check(ok);

        check(signed_msg.msg[0] == MSG_TYPE_COMMIT);
        CommitMessage::from_bytes(signed_msg.msg + 1, signed_msg.msg_len - 1, config_.n_prot_mpc_client, &commit_msg);
    }

    void receive_input_from(size_t client_id) {
        cout << "Server: receive input from client " << client_id << endl;
        SignedMessage signed_msg = recv_signed_msg(
            client_conns[client_id],
            msg_buf + client_id * PER_CLIENT_MSG_BUF_SIZE,
            PER_CLIENT_MSG_BUF_SIZE,
            evidence_buf + client_id * PER_CLIENT_EVIDENCE_BUF_SIZE,
            PER_CLIENT_EVIDENCE_BUF_SIZE
        );

        // TODO: check input
        uint8_t *input = signed_msg.msg;
        // Parse input, see prot_mpc_client.cpp for format detials
        size_t fixed_len = 2 + 4 + RSA_KEY_SIZE
                                + AES_IV_SIZE 
                                + 4;

        check(input[0] == MSG_TYPE_INPUT);
        check(input[1] < N_TEE);
        uint32_t id;
        ::from_bytes(input+2, &id);
        check(id == client_id);

        uint8_t *ct_symkey = input + 2 + 4;
        uint8_t symkey_raw[AES_KEY_SIZE];
        size_t olen;
        int ret;
        mu_inp.lock();
        ret = mbedtls_rsa_rsaes_oaep_decrypt(
            &rsa,
            mbedtls_ctr_drbg_random,
            &ctr_drbg,
            nullptr,
            0,
            &olen,
            ct_symkey,
            symkey_raw,
            AES_KEY_SIZE
        );
        mu_inp.unlock();
#ifndef NDEBUG
        printf("%x\n", -ret);
        fflush(stdout);
#endif
        check(ret == 0);
        check(olen == AES_KEY_SIZE);
#ifndef NDEBUG
        cout << "Server: receive symkey ";
        print_binary(cout, symkey_raw, AES_KEY_SIZE);
        cout << endl;
#endif
        mu_inp.lock();
        check(!input_received[client_id]);
        mu_inp.unlock();
        printf("client_id: %u, trust: %u\n", (unsigned)client_id, commit_msg.trust[client_id].j_);

        mbedtls_cipher_setkey(
            &symkey[client_id],
            symkey_raw,
            AES_KEY_LEN,
            MBEDTLS_ENCRYPT
        ); // AES-CTR uses encrypt mode for both encryption and decryption

        uint8_t *iv = ct_symkey + RSA_KEY_SIZE,
                *ct_len_raw = iv + AES_IV_SIZE,
                *ct = ct_len_raw + 4;
        uint32_t ct_len;
        ::from_bytes(ct_len_raw, &ct_len);

        // TODO: check overflow

        // Decrypt parameter
        uint8_t param_buf[ParamType::size() + AES_BLOCK_SIZE];
        size_t pt_len;
        ret = mbedtls_cipher_crypt(
            &symkey[client_id],
            iv,
            AES_IV_SIZE,
            ct,
            ct_len,
            param_buf,
            &pt_len
        );
        check(ret == 0);
#ifndef NDEBUG
        cout << "Server: decrypt parameter ";
        print_binary(cout, param_buf, pt_len);
        cout << endl;
#endif

        ParamType param = ParamType::from_bytes(param_buf);
        mu_inp.lock();
        secagg_input = secagg_input + param;
        input_received[client_id] = true;
        mu_inp.unlock();
    }

    void receive_inputs() {
        vector<future<void>> ft_inp;
        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            if (commit_msg.trust[i].need_input(PROT_MPC_AMD)) {
                ft_inp.push_back(
                    std::async(
                        [&](size_t client_id) {
                            receive_input_from(client_id);
                        }, i
                    )
                );
                // ft_inp.rbegin()->get();
            }
        }
        for (auto &ft : ft_inp) {
            ft.get();
        }
    }

    void start_computing() {
        cout << "Server: start computing" << endl;
        IDMap id_map(commit_msg.trust);
        size_t n_client = N_TEE;

        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            if (commit_msg.trust[i].need_input(PROT_MPC_AMD)) {
                check(input_received[i]);
            }
            else if (commit_msg.trust[i] == Trust::NOT_TRUST()) {
                ++n_client;
            }
        }
        SecaggConfig config(n_client);
        client.reset(new Client(PROT_MPC_AMD, secagg_input, config));

        cout << "Server: send and receive parameters to group members" << endl;
        // msg_buf[0] = MSG_TYPE_SECAGG;

        const size_t PER_SECAGG_CLIENT_BUF_SIZE = MSG_BUF_SIZE / config.group_size / 2;
        check(PER_SECAGG_CLIENT_BUF_SIZE >= 1 + ParamType::size());
        for (size_t i=0; i<config.group_size; ++i) {
            uint8_t *buf = msg_buf + (i*2)*PER_SECAGG_CLIENT_BUF_SIZE;
            buf[0] = MSG_TYPE_SECAGG;
            ParamType param = client->get_coded_params_to_group_member(i);
            param.to_bytes(buf + 1);
        }

        vector<future<void>> ft_group;
        for (size_t i=0; i<config.group_size; ++i) {
            auto future = std::async(
                [&](size_t i) {
                    uint8_t *buf = msg_buf + (i*2)*PER_SECAGG_CLIENT_BUF_SIZE;
                    auto entity = id_map.to_entity_info(client->group_info().group_member(i));
                    if (entity.is_tee) {
                        switch (entity.id) {
                            case PROT_MPC_SGX:
                                write(*sgx_server_conn, buffer(buf, 1 + ParamType::size()));
                                read(*sgx_server_conn, buffer(buf, 1 + ParamType::size()));
                                break;
                            case PROT_MPC_AMD:
                                // client->set_coded_params_from_group_member(i, param);
                                memcpy(buf + PER_SECAGG_CLIENT_BUF_SIZE, buf, 1 + ParamType::size());
                                break;
                            default:
                                check(0);
                        }
                    }
                    else {
                        write(*client_conns[entity.id], buffer(buf, 1 + ParamType::size()));
                        read(*client_conns[entity.id], buffer(buf, 1 + ParamType::size()));
                    }
                }, i
            );
            ft_group.push_back(std::move(future));
        }
        for (auto &ft : ft_group) {
            ft.get();
        }

        for (size_t i=0; i<config.group_size; ++i) {
            uint8_t *buf = msg_buf + (i*2)*PER_SECAGG_CLIENT_BUF_SIZE;    
            check(msg_buf[0] == MSG_TYPE_SECAGG);
            ParamType param = ParamType::from_bytes(buf + 1);
            client->set_coded_params_from_group_member(i, param);       
        }

        check(client->group_info().group == 0);
        cout << "Server: send parameters to the next group member" << endl;
        unique_ptr<ip::tcp::socket> *peer = nullptr;
        ParamType param;
        if (client->group_info().group == config.n_group - 1) {
            peer = &sgx_server_conn;
            param = client->get_local_aggregation_to_server();
        }
        else {
            auto entity_info = id_map.to_entity_info(client->group_info().next_group_member_info());
            check(!entity_info.is_tee);

            peer = &client_conns[entity_info.id];
            param = client->get_aggregated_param_to_next_group_member();
        }
        param.to_bytes(msg_buf+1);
        write(**peer, buffer(msg_buf, 1 + ParamType::size()));

#ifndef NDEBUG
        cout << client->get_random_polynomial_for_test() << endl;
#endif
    }

public:
    AMDServer(const ProtMPCConfig &config):
        config_(config),
        commit_msg(config.n_prot_mpc_client),
        PER_CLIENT_MSG_BUF_SIZE(MSG_BUF_SIZE / config.n_prot_mpc_client),
        PER_CLIENT_EVIDENCE_BUF_SIZE(EVIDENCE_BUF_SIZE / config.n_prot_mpc_client)
    {
        input_received = vector<char>(config.n_prot_mpc_client, false);
        client_conns = vector<unique_ptr<ip::tcp::socket>>(config.n_prot_mpc_client);
        symkey = vector<mbedtls_cipher_context_t>(config.n_prot_mpc_client);

#ifdef PROT_MPC_TEST
        auto start = high_resolution_clock::now();
#endif
        mbedtls_rsa_init(&rsa);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
        const char pers[] = "pers";

        mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            (const unsigned char*) pers,
            strlen(pers)
        );

        cout << "AMD server: generate rsa key" << endl;
        mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, RSA_KEY_LEN, RSA_E);
        mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

        mbedtls_ctr_drbg_random(&ctr_drbg, (unsigned char*)eid.eid_, SECURITY_PARAMETER_SIZE);

        // Initialize symmetric key contexts
        auto cipher_info = mbedtls_cipher_info_from_values(
            MBEDTLS_CIPHER_ID_AES,
            AES_KEY_LEN,
            MBEDTLS_MODE_CTR
        );
        check(cipher_info != nullptr);
        int ret;
        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            mbedtls_cipher_init(&symkey[i]);
            ret = mbedtls_cipher_setup(&symkey[i], cipher_info);
            check(ret == 0);
        }
#ifdef PROT_MPC_TEST
        auto end = high_resolution_clock::now();
        time_agg += end - start;
#endif
    }

    void run() {
        int ret = 0, ret_ecall = 0;

        listen_and_connect();

#if defined PROT_MPC_TEST
        auto start = high_resolution_clock::now();
#endif

        size_t eid_msg_len = 1 + SECURITY_PARAMETER_SIZE;
        check(eid_msg_len <= MSG_BUF_SIZE);
        msg_buf[0] = MSG_TYPE_EID;
        memcpy(msg_buf + 1, eid.eid_, SECURITY_PARAMETER_SIZE);;
        cout << "Server: send eid to SGX server" << endl;
        write(*sgx_server_conn, buffer(msg_buf, eid_msg_len));

        cout << "Server: receive eid_bc from SGX server" << endl;
        read(*sgx_server_conn, buffer(msg_buf, eid_msg_len));
        check(msg_buf[0] == MSG_TYPE_EID);

        EID::from_bytes(msg_buf + 1, &eid_bc);

        size_t msg_len = 1 + RSA_KEY_SIZE;
        check(msg_len <= MSG_BUF_SIZE);
        msg_buf[0] = MSG_TYPE_AMD_PUBKEY;

        cout << "Server: write public key" << endl;
        mbedtls_mpi N;
        mbedtls_mpi_init(&N);
        ret = mbedtls_rsa_export(&rsa, &N, nullptr, nullptr, nullptr, nullptr);
        check(ret == 0);
        ret = mbedtls_mpi_write_binary(&N, msg_buf + 1, RSA_KEY_SIZE);

        mbedtls_mpi_free(&N);

        cout << "Server: send pubkey to SGX server" << endl;
        write(*sgx_server_conn, buffer(msg_buf, msg_len));

        receive_commit_msg();

        receive_inputs();

#if defined SECAGG_TEST
        auto start = high_resolution_clock::now();
#endif

        start_computing();

#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
        auto end = high_resolution_clock::now();

        time_agg += end - start;
        cout << "Server: Test complete. Elapsed: " << 
            duration_cast<milliseconds>(time_agg).count() << "ms." << endl;
#endif
    }
};

int main(int argc, char* argv[])
{
    ProtMPCConfig config = Args::parse(argc, argv);
    AMDServer *amd_server = new AMDServer(config);

    amd_server->run();
}

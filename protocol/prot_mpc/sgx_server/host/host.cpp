// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <check.h>
#include <limits.h>
#include <stdio.h>
#include <vector>
#include <memory>
#include <future>
#include <mutex>
#include <iostream>
#include <fstream>
#include <chrono>
#include <utility>

#include <asio.hpp>

#include "prog_bc_u.h"
#include "prog_mpc_u.h"

#include "secagg/common.h"
#include "secagg/server.hpp"

#include "constant.h"
#include "config.h"
#include "network.h"

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>

using namespace std::chrono;
using namespace std;
using namespace asio;

oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};

oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

struct Empty {};

struct Args {
    static ProtMPCConfig parse(int argc, char *argv[]) {
        check(argc >= 2);
        return ProtMPCConfig::load(argv[1]);
    }
};

struct ClientThread;

// TODO: shrink buffer sizes used for ecalls
class SGXServer {
    friend struct ClientThread;

public:
    const ProtMPCConfig config_;

    oe_enclave_t *prog_bc_enclave = NULL;
    oe_enclave_t *prog_mpc_enclave = NULL;

    static constexpr size_t MSG_BUF_SIZE = 1024 * 1024 * 24;
    const size_t PER_CLIENT_MSG_BUF_SIZE = 0;
    uint8_t *msg_buf = new uint8_t[MSG_BUF_SIZE];

    static constexpr size_t EVIDENCE_BUF_SIZE = 1024 * 1024 * 24;
    const size_t PER_CLIENT_EVIDENCE_BUF_SIZE = 0;
    uint8_t evidence_buf[EVIDENCE_BUF_SIZE];

    io_context io;
    vector<unique_ptr<ip::tcp::socket>> client_conns;
    unique_ptr<ip::tcp::socket> amd_server_conn;

    EID eids[N_TEE];

    CommitMessage commit_msg;

    unique_ptr<Server> server;

    mutex mu_conn;

#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
    Duration time_agg = Duration(0);
#endif

    void listen();

    void launch_enclaves() {
        uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
        oe_result_t result;

        cout << "Host: create enclave for image:" << "./prog_bc/prog_bc.signed" << endl;
        result = oe_create_prog_bc_enclave(
            "./sgx_server/prog_bc/prog_bc.signed", OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &prog_bc_enclave);
        check(result == OE_OK);

        cout << "Host: create enclave for image:" << "./prog_mpc/prog_mpc.signed" << endl;
        result = oe_create_prog_mpc_enclave(
            "./sgx_server/prog_mpc/prog_mpc.signed", OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &prog_mpc_enclave);
        check(result == OE_OK);

        cout << "Host: initialize enclaves" << endl;
        size_t pubkeys_len = config_.n_prot_mpc_client * ECDSA_PUB_KEY_SIZE;
        check(MSG_BUF_SIZE >= pubkeys_len);

        fstream pubkeys_file("../pubkeys", ios::in | ios::binary);
        check(static_cast<bool>(pubkeys_file));
        uint8_t *pubkeys_buf = msg_buf;
        pubkeys_file.read((char*)pubkeys_buf, pubkeys_len);
        pubkeys_file.close();

        int ret, ret_ecall;
        ret = prog_bc_load_config(prog_bc_enclave, &ret_ecall, config_.n_prot_mpc_client, pubkeys_buf, pubkeys_len);
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);

        ret = prog_mpc_load_config(prog_mpc_enclave, &ret_ecall, config_.n_prot_mpc_client, pubkeys_buf, pubkeys_len);
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);

        uint8_t eid_buf[SECURITY_PARAMETER_SIZE];
        ret = get_prog_mpc_eid(
            prog_mpc_enclave,
            &ret_ecall,
            eid_buf,
            SECURITY_PARAMETER_SIZE
        );
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);

#ifndef NDEBUG
        cout << "Host: get SGX eid" << endl;
        print_binary(cout, eid_buf, SECURITY_PARAMETER_SIZE);
        cout << endl;
#endif

        EID::from_bytes(eid_buf, &eids[PROT_MPC_SGX]);

        cout << "Host: receive eid of AMD server" << endl;
        size_t eid_msg_len = 1 + SECURITY_PARAMETER_SIZE;
        check(eid_msg_len <= MSG_BUF_SIZE);
        read(*amd_server_conn, buffer(msg_buf, eid_msg_len));
        check(msg_buf[0] == MSG_TYPE_EID);
        EID::from_bytes(msg_buf + 1, &eids[PROT_MPC_AMD]);
    }

    void broadcast_eid_bc() {
        int ret, ret_ecall;

        msg_buf[0] = MSG_TYPE_EID;
        uint8_t *eid = msg_buf + 1;
        size_t msg_len = 1 + SECURITY_PARAMETER_SIZE;
        check(MSG_BUF_SIZE >= msg_len);

        cout << "Host: get eid_bc from prog_bc" << endl;
        ret = get_prog_bc_eid(prog_bc_enclave, &ret_ecall, msg_buf + 1, SECURITY_PARAMETER_SIZE);
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);

        cout << "Host: get eid_bc ";
        print_binary(cout, msg_buf + 1, SECURITY_PARAMETER_SIZE);
        cout << endl;

        cout << "Host: send eid_bc to clients" << endl; 
        vector<future<void>> ft_bcs;
        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            std::async(
                [&](size_t client_id) {
                    write(*client_conns[client_id], buffer(msg_buf, msg_len));
                }, i
            );
        }

        for (auto &ft : ft_bcs) {
            ft.get();
        }

        cout << "Host: send eid_bc to AMD server" << endl; 
        write(*amd_server_conn, buffer(msg_buf, msg_len));
    }

    SignedMessage receive_signed_ack_message_from(size_t client_id) {
        // The returned message points to the buffer
        // Be aware of buffer being overwritten and thread safety!!!!!
        check(client_id < config_.n_prot_mpc_client);

        SignedMessage signed_msg = recv_signed_msg(
            client_conns[client_id],
            msg_buf + client_id * PER_CLIENT_MSG_BUF_SIZE,
            PER_CLIENT_MSG_BUF_SIZE,
            evidence_buf + client_id * PER_CLIENT_EVIDENCE_BUF_SIZE,
            PER_CLIENT_EVIDENCE_BUF_SIZE
        );

        return signed_msg;
    }

    void setup_sgx_pubkey() {
        cout << "Host: setup public key from SGX enclave" << endl;
        uint8_t *key_buf = msg_buf;
        const size_t key_buf_size = 1 + RSA_KEY_SIZE;
        check(key_buf_size <= MSG_BUF_SIZE);
        int ret, ret_ecall;
        size_t key_len = 0, evidence_len = 0;
        ret = key_gen(
            prog_mpc_enclave,
            &ret_ecall,
            key_buf,
            &key_len,
            key_buf_size,
            evidence_buf,
            &evidence_len,
            8192
        );
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);

        cout << "Host: setup SGX public key" << endl;
        ret = key_setup(
            prog_bc_enclave,
            &ret_ecall,
            eids[PROT_MPC_SGX].eid_,
            SECURITY_PARAMETER_SIZE,
            evidence_buf,
            evidence_len,
            PROT_MPC_SGX,
            key_buf,
            key_len
        );
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);
    }

    void setup_amd_pubkey() {
        // TODO: veirify the pubkey
        cout << "Hose: receive AMD pubkey from AMD server" << endl;
        size_t msg_len = 1 + RSA_KEY_SIZE;
        check(msg_len <= MSG_BUF_SIZE);
        read(*amd_server_conn, buffer(msg_buf, msg_len));
        int ret, ret_ecall;
        ret = key_setup(
            prog_bc_enclave,
            &ret_ecall,
            eids[PROT_MPC_AMD].eid_,
            SECURITY_PARAMETER_SIZE,
            nullptr,
            0,
            PROT_MPC_AMD,
            msg_buf,
            msg_len
        );
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);
    }

    void save_and_broadcast_commit_msg() {
        int ret, ret_ecall;

        uint8_t *commit_buf = msg_buf;
        size_t commit_buf_len = CommitMessage::fixed_size(config_.n_prot_mpc_client) 
                              + 1024 * N_TEE;
        size_t commit_len = 0, evidence_len = 0;
        check(commit_buf_len <= MSG_BUF_SIZE);
        cout << "Host: get commit message from prog_bc" << endl;
        ret = commit(
            prog_bc_enclave,
            &ret_ecall,
            commit_buf,
            &commit_len,
            commit_buf_len,
            evidence_buf,
            &evidence_len,
            8192
        );
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);
        CommitMessage::from_bytes(commit_buf + 1, commit_len - 1, config_.n_prot_mpc_client, &commit_msg);

        SignedMessage signed_msg {
            .msg = commit_buf,
            .msg_len = (uint32_t)commit_len,
            .sig = evidence_buf,
            .sig_len = (uint32_t)evidence_len
        };
        cout << "Host: send commit message to clients" << endl;
        vector<future<void>> ft_send_commits;
        ft_send_commits.reserve(config_.n_prot_mpc_client);
        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            ft_send_commits.push_back(
                std::async(
                    [&](size_t client_id) {
                        send_signed_msg(client_conns[client_id], signed_msg);
                    }, i
                )
            );
        }
        cout << "Host: send commit message to AMD server" << endl;
        ft_send_commits.push_back(
            std::async(
                [&]() {
                    send_signed_msg(amd_server_conn, signed_msg);
                }
            )
        );

        cout << "Host: setup commit message for prog_mpc enclave" << endl;
        ret = setup_commit_msg(prog_mpc_enclave, &ret_ecall, commit_buf, commit_len, evidence_buf, evidence_len);
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);

        for (auto &ft : ft_send_commits) {
            ft.get();
        }
    }

    void setup_enclave_symkeys() {
        int ret, ret_ecall;
        vector<future<SignedMessage>> ft_inp;
#ifndef NDEBUG
        cout << "Host: setup symkeys and receive inputs" << endl;
#endif
        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            const auto &trust = commit_msg.trust[i];
            if (trust.need_input(PROT_MPC_SGX)) {
                ft_inp.push_back(
                    std::async(
                        [&](size_t client_id) {
                            return recv_signed_msg(
                                client_conns[client_id],
                                msg_buf + client_id * PER_CLIENT_MSG_BUF_SIZE,
                                PER_CLIENT_MSG_BUF_SIZE,
                                evidence_buf + client_id * PER_CLIENT_EVIDENCE_BUF_SIZE,
                                PER_CLIENT_EVIDENCE_BUF_SIZE
                            );
                        }, i
                    )
                );
            }
        }
#ifndef NDEBUG
        cout << "Host: forward inputs to the enclave" << endl;
#endif
        for (auto &ft : ft_inp) {
            SignedMessage signed_msg = ft.get();
            ret = setup_input(
                prog_mpc_enclave,
                &ret_ecall,
                signed_msg.msg,
                signed_msg.msg_len,
                signed_msg.sig,
                signed_msg.sig_len
            );
            check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);
        }
#ifndef NDEBUG
        cout << "Host: done" << endl;
#endif        
    }

    void start_computing() {
        IDMap id_map(commit_msg.trust);
        size_t n_client = N_TEE;
        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            if (commit_msg.trust[i] == Trust::NOT_TRUST()) {
                ++n_client;
            }
        }
        SecaggConfig secagg_config(n_client);
        GroupInfo info(PROT_MPC_SGX, secagg_config);
        server.reset(new Server(secagg_config));

        int ret, ret_ecall;
        // msg_buf[0] = MSG_TYPE_SECAGG;

        const size_t PER_SECAGG_CLIENT_BUF_SIZE = MSG_BUF_SIZE / secagg_config.group_size / 2;
        cout << PER_SECAGG_CLIENT_BUF_SIZE << " " << ParamType::size() << endl;
        check(PER_SECAGG_CLIENT_BUF_SIZE >= 1 + ParamType::size());
        for (size_t i=0; i<secagg_config.group_size; ++i) {
            uint8_t *buf = msg_buf + (i*2)*PER_SECAGG_CLIENT_BUF_SIZE;
            buf[0] = MSG_TYPE_SECAGG;
            ret = get_params_to(prog_mpc_enclave, &ret_ecall, i, buf + 1, ParamType::size());
            check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);            
        }
        cout << "Host: send and receive parameters to group members" << endl;
        vector<future<void>> ft_group;
        for (size_t i=0; i<secagg_config.group_size; ++i) {
            auto future = std::async([&](size_t i) {
                    uint8_t *buf = msg_buf + (i*2)*PER_SECAGG_CLIENT_BUF_SIZE;
                    auto entity = id_map.to_entity_info(info.group_member(i));
                        if (entity.is_tee) {
                            switch (entity.id) {
                                case PROT_MPC_SGX:
                                    // ret = set_params_from(prog_mpc_enclave, &ret_ecall, i, , ParamType::size());
                                    // check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);
                                    memcpy(buf + PER_SECAGG_CLIENT_BUF_SIZE, buf, 1 + ParamType::size());
                                    break;
                                case PROT_MPC_AMD:
                                    write(*amd_server_conn, buffer(buf, 1 + ParamType::size()));
                                    read(*amd_server_conn, buffer(buf + PER_SECAGG_CLIENT_BUF_SIZE, 1 + ParamType::size()));
                                    break;
                                default:
                                    check(0);
                            }
                        }
                        else {
                            write(*client_conns[entity.id], buffer(buf, 1 + ParamType::size()));
                            read(*client_conns[entity.id], buffer(buf + PER_SECAGG_CLIENT_BUF_SIZE, 1 + ParamType::size()));
                        }
                }, i
            );
            ft_group.push_back(std::move(future));
        }
        for (auto &ft : ft_group) {
            ft.get();
        }

        cout << "Host: set parameters from group members" << endl;
        for (size_t i=0; i<secagg_config.group_size; ++i) {
            uint8_t *buf = msg_buf + (i*2 + 1) * PER_SECAGG_CLIENT_BUF_SIZE;
            check(buf[0] == MSG_TYPE_SECAGG);
            ret = set_params_from(prog_mpc_enclave, &ret_ecall, i, buf + 1, ParamType::size());
            check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);
        }
        check(info.group == 0);

        cout << "Host: send parameters to the next group" << endl;
        ret = get_params_to(prog_mpc_enclave, &ret_ecall, secagg_config.group_size, msg_buf+1, ParamType::size());
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);

        if (info.group == secagg_config.n_group - 1) {
            memmove(msg_buf + 1 + info.id_in_group * PER_SECAGG_CLIENT_BUF_SIZE, msg_buf + 1, ParamType::size());
        }
        else {
            auto entity_info = id_map.to_entity_info(info.next_group_member_info());
            write(*client_conns[entity_info.id], buffer(msg_buf, 1 + ParamType::size()));
        }

        cout << "Host: receive parameters from the final group" << endl;
        vector<future<void>> ft_fin_group;
        for (size_t i=0; i<secagg_config.group_size; ++i) {
            auto future = std::async(
                [&](size_t i) {
                    uint8_t *buf = msg_buf + (i*2) * PER_SECAGG_CLIENT_BUF_SIZE;
                    auto entity_info = id_map.to_entity_info(
                        GroupInfo(secagg_config.n_group-1, i, secagg_config)
                    );
                    if (entity_info.is_tee) {
                        switch (entity_info.id) {
                            case PROT_MPC_SGX:
                                // Do nothing in this case since the parameter has been aggregated
                                break;
                            case PROT_MPC_AMD:
                                read(*amd_server_conn, buffer(buf, 1 + ParamType::size()));      
                                break;
                            default:
                                check(0);                    
                        }                
                    }
                    else {
                        read(*client_conns[entity_info.id], buffer(buf, 1 + ParamType::size()));
                    }
                }, i
            );
            ft_fin_group.push_back(std::move(future));
        }
        for (auto &ft : ft_fin_group) {
            ft.get();
        }
        for (size_t i=0; i<secagg_config.group_size; ++i) {
            uint8_t *buf = msg_buf + (i*2) * PER_SECAGG_CLIENT_BUF_SIZE;
            check(buf[0] == MSG_TYPE_SECAGG);
            ParamType param = ParamType::from_bytes(buf + 1);
#ifndef NDEBUG
            cout << "Host: aggregation from id_in_group " << i << " " << param << endl;
#endif
            server->set_aggregation_from_client(i, param);
        }

        ParamType aggregation = server->aggregate();
        cout << "Host: broadcast aggregation to all clients" << endl;
        msg_buf[0] = MSG_TYPE_OUTPUT;
        aggregation.to_bytes(msg_buf + 1);
        vector<future<void>> ft_outp;
        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            ft_outp.push_back(
                std::async(
                    [&](size_t i) {
                        write(*client_conns[i], buffer(msg_buf, 1 + ParamType::size()));
                    }, i
                )
            );
        }
        for (auto &ft : ft_outp) {
            ft.get();
        }

#ifndef NDEBUG
        size_t len;
        ret = get_random_polynomial_for_test(prog_mpc_enclave, &ret_ecall, msg_buf, &len, 40960);
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);
        printf("Host: polynomial %s\n", (char*)msg_buf);
#endif
    }

public:
    explicit SGXServer(const ProtMPCConfig &config):
      config_(config),
      commit_msg(0),
      PER_CLIENT_MSG_BUF_SIZE(MSG_BUF_SIZE / config.n_prot_mpc_client),
      PER_CLIENT_EVIDENCE_BUF_SIZE(EVIDENCE_BUF_SIZE / config.n_prot_mpc_client)
    {
        client_conns = vector<unique_ptr<ip::tcp::socket>>(config_.n_prot_mpc_client);
    }

    void run() {
        int ret = 0, ret_ecall = 0;

        listen();

#ifdef PROT_MPC_TEST
        auto start = high_resolution_clock::now();
#endif

        launch_enclaves();

        broadcast_eid_bc();

        cout << "Host: prog_bc setup" << endl;

        vector<future<SignedMessage>> ft_acks;

        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            ft_acks.push_back(
                std::async(
                    [&](size_t client_id) {
                        SignedMessage signed_ack_msg = receive_signed_ack_message_from(client_id);
#ifndef NDEBUG
                        cout << "Host: receive signature ";
                        print_binary(cout, signed_ack_msg.sig, signed_ack_msg.sig_len);
                        cout << endl;
                        cout << "with message ";
                        print_binary(cout, signed_ack_msg.msg, signed_ack_msg.msg_len);
                        cout << endl;
#endif
                        return signed_ack_msg;
                    }, i
                )
            );
        }

        for (size_t i=0; i<config_.n_prot_mpc_client; ++i) {
            SignedMessage signed_ack_msg = ft_acks[i].get();
            ret = setup(prog_bc_enclave, &ret_ecall, signed_ack_msg.sig, signed_ack_msg.sig_len, signed_ack_msg.msg, signed_ack_msg.msg_len);
            check(ret == OE_OK &&ret_ecall == MY_ECALL_SUCCESS);
        }

        setup_sgx_pubkey();
        setup_amd_pubkey();

        save_and_broadcast_commit_msg();
        
        setup_enclave_symkeys();

#ifdef SECAGG_TEST
        auto start = high_resolution_clock::now();
#endif

        start_computing();
        
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
        auto end = high_resolution_clock::now();

        time_agg += end - start;
        cout << "Host: Test complete. Elapsed: " << 
                duration_cast<milliseconds>(time_agg).count() << "ms." << endl;
#endif
    }

    void test_attestation() {
        launch_enclaves();

        check(prog_bc_enclave != NULL);
        // TODO
        int ret, ret_ecall;

        uint8_t *output_buf = msg_buf;
        size_t output_buf_size = MSG_BUF_SIZE;

        size_t evidence_size = 0;

        ret = ::test_attestation(prog_mpc_enclave, &ret_ecall, output_buf, output_buf_size, evidence_buf, &evidence_size, EVIDENCE_BUF_SIZE);
        check(ret == OE_OK && ret_ecall == MY_ECALL_SUCCESS);

        cout << "Initialize verifier" << endl;
        ret = oe_verifier_initialize();
        check(ret == OE_OK);

        cout << "Verify evidence" << endl;
        oe_claim_t *claims = nullptr;
        size_t claims_size = 0;
        ret = oe_verify_evidence(
            &sgx_remote_uuid,
            evidence_buf,
            evidence_size,
            nullptr,
            0,
            nullptr,
            0,
            &claims,
            &claims_size
        );

        check(ret == OE_OK);
    }
};

void SGXServer::listen() {
    cout << "Host: listen to AMD server" << endl;
    ip::tcp::acceptor server_acceptor(io, ip::tcp::endpoint(ip::tcp::v4(), SGX_SERVER_LISTEN_SERVER_PORT));
    amd_server_conn.reset(new ip::tcp::socket(io));
    server_acceptor.accept(*amd_server_conn);

    cout << "Host: listen to clients" << endl;
    ip::tcp::acceptor client_acceptor(io, ip::tcp::endpoint(ip::tcp::v4(), SGX_SERVER_LISTEN_CLIENT_PORT));

    vector<future<void>> ft_conns;
    ft_conns.reserve(config_.n_prot_mpc_client);
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
                    cout << "Host: accept client connection with id " << client_id << endl;
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

int main(int argc, char* argv[])
{
    auto config = Args::parse(argc, argv);
    SGXServer *sgx_server = new SGXServer(config);

    sgx_server->run();
}

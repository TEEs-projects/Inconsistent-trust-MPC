#include <iostream>
#include <fstream>
#include <exception>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/rsa.h>
#include <mbedtls/cipher.h>
#include <mbedtls/error.h>
#include <string.h>
#include <string>
#include <future>
#include <mutex>
#include <chrono>

#include "config.h"
#include "constant.h"
#include "network.h"

#include "secagg/client.hpp"
#include "secagg/common.h"

#include "asio.hpp"
#include "evidence_verifier.h"

using namespace std::chrono;
using namespace std;
using namespace asio;

struct Args {
    ParamType param;
    Trust trust;
    ProtMPCClientConfig config;

    static Args parse(int argc, char *argv[]) {
        if (argc < 4) {
            cout << "Usage: client [id] [trust] [path_to_config]" << endl;
            abort();
        }

        Args ret;

        ret.config = ProtMPCClientConfig::load_with_id(argv[3], stoi(argv[1]));

        ret.trust = Trust(stoi(argv[2]));

        ret.param = ParamType::random();

        return ret;
    }
};

class ProtMPCClient {
private:
    ParamType param_;
    Trust trust_;
    ProtMPCClientConfig config_;

    IDMap id_map;

    EID eid_bc;
    CommitMessage commit_msg;

    static constexpr size_t MSG_BUF_SIZE = 1024 * 1024 * 10;
    uint8_t *msg_buf = new uint8_t[MSG_BUF_SIZE];

    static constexpr size_t EVIDENCE_BUF_SIZE = (1024 * 10);
    uint8_t evidence_buf[EVIDENCE_BUF_SIZE];

    io_context io;
    unique_ptr<ip::tcp::socket> server_conn[N_TEE];
    vector<unique_ptr<ip::tcp::socket>> client_conn;
    
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecdsa_context ecdsa;
    mbedtls_rsa_context rsa[N_TEE];

    mbedtls_cipher_context_t symkey[N_TEE];

    EvidenceVerifier evidence_verifier;

    unique_ptr<Client> client;
    unique_ptr<SecaggConfig> secagg_config;

#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
    Duration time_agg = Duration(0);
    Duration time_active = Duration(0);
#endif

    // TODO: set connection timeout
    void connect_server() {
        uint8_t id_buf[4];
        ::to_bytes(id_buf, config_.client_id);
        cout << "Client: connect to sgx server" << endl;
        ip::tcp::endpoint sgx_server_ep(
            ip::tcp::endpoint(
                config_.prot_mpc_config.sgx_server_ip, SGX_SERVER_LISTEN_CLIENT_PORT
            )
        );
        while (true) {
            try {
                server_conn[PROT_MPC_SGX]->connect(sgx_server_ep);
                break;
            } catch (const std::exception &e) {
                this_thread::sleep_for(CONNECT_PERIOD);
            }
        }
        write(*server_conn[PROT_MPC_SGX], buffer(id_buf, 4));

        cout << "Client: connect to amd server" << endl;
        ip::tcp::endpoint amd_server_ep(
            ip::tcp::endpoint(config_.prot_mpc_config.amd_server_ip, AMD_SERVER_PORT
            )
        );        
        while (true) {
            try {
                server_conn[PROT_MPC_AMD]->connect(amd_server_ep);
                break;
            } catch (const std::exception &e) {
                this_thread::sleep_for(CONNECT_PERIOD);
            }
        }
        write(*server_conn[PROT_MPC_AMD], buffer(id_buf, 4));

        read(*server_conn[PROT_MPC_SGX], buffer(msg_buf, 1));
        check(msg_buf[0] == MSG_OK);
        read(*server_conn[PROT_MPC_AMD], buffer(msg_buf, 1));
        check(msg_buf[0] == MSG_OK);
    }

    EID receive_eid_bc_from_server() {
        size_t msg_len = 1 + SECURITY_PARAMETER_SIZE;
        uint8_t *eid_buf = msg_buf + 1;
        check(MSG_BUF_SIZE >= msg_len);

        cout << "Client: receive eid_bc from sgx server" << endl;
        size_t n_read = read(*server_conn[PROT_MPC_SGX], buffer(msg_buf, msg_len));
        check(n_read == msg_len);

        check(msg_buf[0] == MSG_TYPE_EID);
        cout << "Client: received eid_bc ";
        print_binary(cout, msg_buf+1, SECURITY_PARAMETER_SIZE);
        cout << endl;
        EID eid;
        EID::from_bytes(msg_buf + 1, &eid);

        return eid;
    }

    void sign_msg_and_send_to(
        const uint8_t *msg,
        size_t msg_len,
        unique_ptr<ip::tcp::socket> &conn
    ) {
        uint8_t hash[32];
        mbedtls_sha256(msg_buf, msg_len, hash, 0);

        size_t sig_len = 0;
        int ret;
        ret = mbedtls_ecdsa_write_signature(
            &ecdsa,
            MBEDTLS_MD_SHA256,
            hash,
            32,
            evidence_buf,
            EVIDENCE_BUF_SIZE,
            &sig_len,
            mbedtls_ctr_drbg_random,
            &ctr_drbg
        );
        
        SignedMessage signed_msg{
            .msg = msg_buf,
            .msg_len = (uint32_t)msg_len,
            .sig = evidence_buf,
            .sig_len = (uint32_t)sig_len
        };
        send_signed_msg(conn, signed_msg);
    }

    void send_ack_msg_to_server() {
        size_t msg_len = 1 + AckMessage::size();
        check(msg_len <= MSG_BUF_SIZE);
        msg_buf[0] = MSG_TYPE_ACK;
        AckMessage ack_msg{config_.client_id, eid_bc, trust_};
        printf("Client: send ack_msg. id: %u, trust: %u\n", config_.client_id, trust_.j_);
        uint8_t *cur = ack_msg.to_bytes(msg_buf + 1, MSG_BUF_SIZE);

        cout << "Sign and send ack message" << endl;
        sign_msg_and_send_to(msg_buf, cur-msg_buf, server_conn[PROT_MPC_SGX]);
    }

    CommitMessage receive_and_verify_commit_msg_from_server() {
        SignedMessage signed_msg = recv_signed_msg(
            server_conn[PROT_MPC_SGX],
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
        CommitMessage commit_msg(0);
        CommitMessage::from_bytes(
            signed_msg.msg + 1,
            signed_msg.msg_len - 1,
            config_.prot_mpc_config.n_prot_mpc_client,
            &commit_msg
        );

        return commit_msg;
    }

    void send_encrypted_key_and_param_to_tee(size_t tee_id, const ParamType &param) {
// +------------------+--------+-----------+------------------+----+---------+---------+
// | 1                | 1      | 4         | 256              | 16 | 4       | CTX_LEN |
// +------------------+--------+-----------+------------------+----+---------+---------+
// | MSG_TYPE: INPUT  | TEE_ID | CLIENT_ID | ENCRYPTED_SYMKEY | IV | CTX_LEN | CTX     |
// +------------------+--------+-----------+------------------+----+---------+---------+
        uint8_t symkey_raw[AES_KEY_SIZE];
        uint8_t iv[AES_IV_SIZE];
        mbedtls_ctr_drbg_random(&ctr_drbg, symkey_raw, AES_KEY_SIZE);
        mbedtls_ctr_drbg_random(&ctr_drbg, iv, AES_IV_SIZE);
        size_t required_len = 2 + 4 + RSA_KEY_SIZE
                                + AES_IV_SIZE 
                                + 4 
                                + ParamType::size()
                                + AES_BLOCK_SIZE;
        check(MSG_BUF_SIZE >= required_len);
        msg_buf[0] = MSG_TYPE_INPUT;
        msg_buf[1] = (uint8_t)tee_id;
        uint8_t *ct = ::to_bytes(msg_buf + 2, (uint32_t)config_.client_id);

        uint8_t param_buf[ParamType::size()];
        param.to_bytes(param_buf);

#ifndef NDEBUG
        cout << "Client: encrypt parameter: ";
        print_binary(cout, param_buf, ParamType::size());
        cout << endl;
        cout << "Client: with symkey: ";
        print_binary(cout, symkey_raw, AES_KEY_SIZE);
        cout << endl;
#endif

        int ret;
        ret = mbedtls_rsa_rsaes_oaep_encrypt(
            &rsa[tee_id],
            &mbedtls_ctr_drbg_random,
            &ctr_drbg,
            nullptr,
            0,
            AES_KEY_SIZE,
            symkey_raw,
            ct
        );
        check(ret == 0);

        ct += RSA_KEY_SIZE;
        memcpy(ct, iv, AES_IV_SIZE);
        ct += AES_IV_SIZE;

        mbedtls_cipher_setkey(
            &symkey[tee_id],
            symkey_raw,
            AES_KEY_LEN,
            MBEDTLS_ENCRYPT
        );
        size_t olen = 0;
        ret = mbedtls_cipher_crypt(
            &symkey[tee_id],
            iv,
            AES_IV_SIZE,
            param_buf,
            ParamType::size(),
            ct+4,
            &olen
        );
        check(ret == 0);
        ::to_bytes(ct, (uint32_t)olen);
        
        size_t msg_len = ct - msg_buf + 4 + olen;
        sign_msg_and_send_to(msg_buf, msg_len, server_conn[tee_id]);
    }

    unique_ptr<ip::tcp::socket> &select_peer(const EntityInfo &info) {
        if (info.is_tee) {
            check(info.id < N_TEE);
            return server_conn[info.id];
        }
        else {
            check(info.id < config_.prot_mpc_config.n_prot_mpc_client);
            return client_conn[info.id];
        }
    }

    ParamType loop;

    ParamType recv_param_from(const EntityInfo &info) {
        if (!info.is_tee && info.id == config_.client_id) {
            return loop;
        }

        unique_ptr<ip::tcp::socket> &peer = select_peer(info);

        size_t msg_len = 1 + ParamType::size();
        check(MSG_BUF_SIZE >= msg_len);

        read(*peer, buffer(msg_buf, msg_len));
        check(msg_buf[0] == MSG_TYPE_SECAGG);

        return ParamType::from_bytes(msg_buf + 1);
    }

    void send_param_to(const EntityInfo &info, const ParamType &param) {
        if (!info.is_tee && info.id == config_.client_id) {
            loop = param;
            return;
        }

        unique_ptr<ip::tcp::socket> &peer = select_peer(info);

        size_t msg_len = 1 + ParamType::size();
        check(MSG_BUF_SIZE >= msg_len);
        msg_buf[0] = MSG_TYPE_SECAGG;

        param.to_bytes(msg_buf + 1);
        if (info.is_tee) {
            write(*peer, buffer(msg_buf, msg_len));
        }
        else {
            write(*peer, buffer(msg_buf, msg_len));
        }
    }

    ParamType receive_param_from_prev_group() {
        auto prev_entity = id_map.to_entity_info(
            client->group_info().prev_group_member_info()
        );
        return recv_param_from(prev_entity);
    }

    void send_coded_params_to_group_member(size_t id_in_group, const ParamType &param) {
        auto entity = id_map.to_entity_info(
            client->group_info().group_member(id_in_group)
        );
        send_param_to(entity, param);
    }

    ParamType receive_coded_params_from_group_member(size_t id_in_group) {
        auto entity = id_map.to_entity_info(
            client->group_info().group_member(id_in_group)
        );
        return recv_param_from(entity);
    }

    void send_to_next_level() {
        EntityInfo info;
        ParamType param;
        if (client->group_info().group == secagg_config->n_group - 1) {
            info = EntityInfo{true, PROT_MPC_SGX};
            param = client->get_local_aggregation_to_server();
        }
        else {
            info = id_map.to_entity_info(
                client->group_info().next_group_member_info()
            );
            param = client->get_aggregated_param_to_next_group_member();
        }
        send_param_to(info, param);
    }

public:
    ProtMPCClient(
        const ParamType &param, 
        const Trust &trust,
        const ProtMPCClientConfig &config
    ): param_(param), trust_(trust), config_(config), commit_msg(0)
    {
        size_t n_prot_mpc_client = config.prot_mpc_config.n_prot_mpc_client;
        check(config.client_id < n_prot_mpc_client);
        client_conn = vector<unique_ptr<ip::tcp::socket>>(n_prot_mpc_client);

        cout << "init entropy and ctr_drbg" << endl;
        int ret;
        const char *pers = "ecdsa";
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        ret = mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func,
            &entropy,
            (const unsigned char *) pers,
            strlen(pers)
        );
        check(ret == 0);

        cout << "Load pre-generated key pair" << endl;
        fstream key_file("../privkeys", ios::in | ios::binary);
        check(static_cast<bool>(key_file));
        key_file.seekp(ECDSA_PRIV_KEY_SIZE * config.client_id, ios::beg);
        check(MSG_BUF_SIZE >= ECDSA_PRIV_KEY_SIZE);
        key_file.read((char*)msg_buf, ECDSA_PRIV_KEY_SIZE);
        key_file.close();

        mbedtls_ecp_keypair keypair;
        mbedtls_ecp_keypair_init(&keypair);
        
        ret = mbedtls_ecp_read_key(
            ECDSA_GROUP,
            &keypair,
            msg_buf,
            ECDSA_PRIV_KEY_SIZE
        );
        if (ret != 0) {
            cout << "ecp_read_key failed, ret " << ret << endl;
            abort();
        }

        mbedtls_ecdsa_init(&ecdsa);
        ret = mbedtls_ecdsa_from_keypair(&ecdsa, &keypair);
        check(ret == 0);

        cout << "Load and check public key" << endl;
        size_t pubkeys_len = config_.prot_mpc_config.n_prot_mpc_client * ECDSA_PUB_KEY_SIZE;
        check(MSG_BUF_SIZE >= pubkeys_len);

        fstream pubkeys_file("../pubkeys", ios::in | ios::binary);
        check(static_cast<bool>(pubkeys_file));
        uint8_t *pubkeys_buf = msg_buf;
        pubkeys_file.read((char*)pubkeys_buf, pubkeys_len);
        pubkeys_file.close();

        mbedtls_ecp_point Q;
        mbedtls_ecp_point_init(&Q);
        mbedtls_ecp_group ECP_GROUP;
        mbedtls_ecp_group_init(&ECP_GROUP);
        mbedtls_ecp_group_load(&ECP_GROUP, ECDSA_GROUP);
        ret = mbedtls_ecp_point_read_binary(
            &ECP_GROUP,
            &Q,
            pubkeys_buf + ECDSA_PUB_KEY_SIZE * config_.client_id,
            ECDSA_PUB_KEY_SIZE
        );
        check(ret == 0);
        cout << "Set public key" << endl;
        ret = mbedtls_ecp_set_public_key(
            ECDSA_GROUP,
            &keypair,
            &Q
        );
        check(ret == 0);
        cout << "Check public key" << endl;
        ret = mbedtls_ecp_check_pub_priv(
            &keypair, &keypair, mbedtls_ctr_drbg_random, &ctr_drbg
        );
        check(ret == 0);

        mbedtls_ecp_group_free(&ECP_GROUP);
        mbedtls_ecp_point_free(&Q);

        mbedtls_ecp_keypair_free(&keypair);

        for (size_t i=0; i<N_TEE; ++i) {
            mbedtls_rsa_init(&rsa[i]);
            mbedtls_rsa_set_padding(&rsa[i], MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
        }

        auto cipher_info = mbedtls_cipher_info_from_values(
            MBEDTLS_CIPHER_ID_AES,
            AES_KEY_LEN,
            MBEDTLS_MODE_CTR
        );
        check(cipher_info != nullptr);
        for (size_t i=0; i<N_TEE; ++i) {
            mbedtls_cipher_init(&symkey[i]);
            ret = mbedtls_cipher_setup(&symkey[i], cipher_info);
            check(ret == 0);
        }

        for (size_t i=0; i<N_TEE; ++i) {
            server_conn[i] = unique_ptr<ip::tcp::socket>(new ip::tcp::socket(io));
        }
    }

    void run() {
        size_t n_prot_mpc_client = config_.prot_mpc_config.n_prot_mpc_client;
        cout << "Connect to the server and other clients" << endl;
        connect_server();

#ifdef PROT_MPC_TEST
        auto start = high_resolution_clock::now();
        auto start_commit = high_resolution_clock::now();
#endif

        cout << "Receive eid_bc from the server" << endl;
        eid_bc = receive_eid_bc_from_server();

        cout << "Construct and send ack message to the server" << endl;
        send_ack_msg_to_server();

        cout << "Receive and verify commit message from server" << endl;
        commit_msg = receive_and_verify_commit_msg_from_server();
        check(commit_msg.eid_bc == eid_bc);
        check(commit_msg.trust[config_.client_id] == trust_);

        mbedtls_mpi N, E;
        mbedtls_mpi_init(&N);
        mbedtls_mpi_init(&E);
        mbedtls_mpi_lset(&E, RSA_E);
        for (size_t i=0; i<N_TEE; ++i) {
            mbedtls_mpi_read_binary(
                &N,
                commit_msg.pk[i].data(),
                commit_msg.pk[i].size()
            );
            mbedtls_rsa_import(
                &rsa[i], &N, nullptr, nullptr, nullptr, &E
            );
        }
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);

#ifdef PROT_MPC_TEST
        cout << "Client: Total time for committing: " << 
            duration_cast<milliseconds>(high_resolution_clock::now() - start_commit).count() << "ms." << endl;        
#endif

#ifndef NDEBUG
        cout << "Client: start secure aggregation with input" << param_ << endl;
#endif

#ifdef SECAGG_TEST
        auto start = high_resolution_clock::now();
#endif

#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
            auto time_compute = Duration(0);
            auto time_communicate = Duration(0);
            Time start_unit;
#endif

#ifdef PROT_MPC_TEST
        auto end_commit = high_resolution_clock::now();
        auto time_commit = end_commit - start_commit;
        cout << "Client: Total time for comfirming commit message: " << 
            duration_cast<milliseconds>(time_commit).count() << "ms." << endl;
#endif
        if (trust_.is_complete_trust()) {
#ifdef PROT_MPC_TEST
            auto start_send = high_resolution_clock::now();
#endif  
            cout << "Client: send the input to the TEE" << endl;
            send_encrypted_key_and_param_to_tee(trust_.tee(), param_);
#ifdef PROT_MPC_TEST
            auto end_send = high_resolution_clock::now();
            auto time_send = end_send - start_send;
            cout << "Client: Total time for sending inputs: " << 
                duration_cast<milliseconds>(time_send).count() << "ms." << endl;
#endif  
        }
        else if (trust_ == Trust::PARTIAL_TRUST()) {
#ifdef PROT_MPC_TEST
            auto start_send = high_resolution_clock::now();
#endif 
            cout << "Client: distribute shares of inputs to TEEs" << endl;
            ParamType cur = param_;
            for (size_t i=0; i<N_TEE-1; ++i) {
                ParamType mask = ParamType::random();
                send_encrypted_key_and_param_to_tee(i, mask);
                cur = cur - mask;
            }
            send_encrypted_key_and_param_to_tee(N_TEE-1, cur);
#ifdef PROT_MPC_TEST
            auto end_send = high_resolution_clock::now();
            auto time_send = end_send - start_send;
            cout << "Client: Total time for sending inputs: " << 
                duration_cast<milliseconds>(time_send).count() << "ms." << endl;
#endif 
        }
        else {
            id_map = IDMap(commit_msg.trust);
            size_t n_client = N_TEE;
            for (size_t i=0; i<n_prot_mpc_client; ++i) {
                if (commit_msg.trust[i] == Trust::NOT_TRUST()) {
                    ++n_client;
                }
            }
            secagg_config.reset(new SecaggConfig(n_client));

            cout << "Client: connect clients" << endl;
            auto ep = [&](size_t id){ return 
                ip::tcp::endpoint(
                        config_.prot_mpc_config.client_ips[id], CLIENT_PORT + id); };
            ip::tcp::acceptor acceptor(io, ip::tcp::endpoint(
                ip::tcp::v4(), CLIENT_PORT + config_.client_id
            ));
            // TODO: use multithread to connect clients
            printf("Client %u: bind port %u\n", config_.client_id, ep(config_.client_id).port());
            fflush(stdout);

            vector<future<void>> ft_conns;
            mutex mu_conn;
            for (size_t i=0; i<config_.client_id; ++i) {
                if (commit_msg.trust[i] == Trust::NOT_TRUST()) {
                    unique_ptr<ip::tcp::socket> conn(new ip::tcp::socket(io));
                    acceptor.accept(*conn);
                    ft_conns.push_back(
                        std::async(
                            [&](unique_ptr<ip::tcp::socket> conn) {
                                size_t client_id = confirm_client_id(conn);
                                check(client_id < n_prot_mpc_client);   
#ifndef NDEBUG
                                printf("Client: accept connection from client %u\n", (unsigned)client_id);
                                fflush(stdout);
#endif                                 
                                mu_conn.lock();
                                check(client_conn[client_id] == nullptr);
                                check(commit_msg.trust[client_id] == Trust::NOT_TRUST());
                                client_conn[client_id].reset(conn.release());
                                mu_conn.unlock();
                            }, std::move(conn)
                        )
                    );
                }
            }
            for (size_t i=config_.client_id+1; i<n_prot_mpc_client; ++i) {
                if (commit_msg.trust[i] == Trust::NOT_TRUST()) {
                    auto future = std::async(
                        [&](size_t i) {
                            uint8_t id_buf[4];
                            ::to_bytes(id_buf, config_.client_id);
#ifndef NDEBUG
                            cout << "Client: connect to client " << i << endl;
#endif
                            ip::tcp::endpoint peer_ep = ep(i);
                            client_conn[i] = unique_ptr<ip::tcp::socket>(new ip::tcp::socket(io));
                            while (true) {
                                try {
                                    client_conn[i]->connect(peer_ep);
                                    break;
                                } catch (const std::exception &e) {
                                    this_thread::sleep_for(CONNECT_PERIOD);
                                }
                            }
                            write(*client_conn[i], buffer(id_buf, 4));
                        }, i
                    );
                    ft_conns.push_back(std::move(future));
                }
            }
            for (auto &ft : ft_conns) {
                ft.get();
            }

            size_t sec_agg_id = id_map.to_sec_agg_id(EntityInfo{false, config_.client_id});
            cout << "Client: start secure aggregation with client id " << sec_agg_id << endl;
            client.reset(
                new Client(sec_agg_id, param_, *secagg_config)
            );
            cout << "Client: send parameters to group members" << endl;
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
            start_unit = high_resolution_clock::now();
#endif            
            vector<ParamType> params_to_sent;
            params_to_sent.reserve(secagg_config->group_size);
            for (size_t i=0; i<secagg_config->group_size; ++i) {
                params_to_sent.push_back(client->get_coded_params_to_group_member(i));
            }
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
            time_compute += high_resolution_clock::now() - start_unit;
            start_unit = high_resolution_clock::now();
#endif
            vector<future<void>> ft_group;
            vector<ParamType> params_received(n_client);
            for (size_t i=0; i<secagg_config->group_size; ++i) {
                ft_group.push_back(
                    std::async(
                        [&](size_t i) {
                            send_coded_params_to_group_member(i, params_to_sent[i]);
                            params_received[i] = receive_coded_params_from_group_member(i);;
                        }, i
                    )
                );
            }
            for (auto &ft : ft_group) {
                ft.get();
            }

            ParamType prev_group_param;
            if (client->group_info().group != 0) {
                try {
                    prev_group_param = receive_param_from_prev_group();
                } catch (const std::exception &e) {
                    cout << e.what() << endl;
                    return;
                }
            }
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
            time_communicate += high_resolution_clock::now() - start_unit;
            start_unit = high_resolution_clock::now();
#endif
            if (client->group_info().group != 0) {
                client->set_aggregated_param_from_prev_group_member(prev_group_param);
            }
            for (size_t i=0; i<secagg_config->group_size; ++i) {
                client->set_coded_params_from_group_member(i, params_received[i]);
            }
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
            time_compute += high_resolution_clock::now() - start_unit;
            start_unit = high_resolution_clock::now();
#endif
            // check(n_dropped <= secagg_config->n_drop);
            cout << "Client: send local aggregation to the next group/server" << endl;
            send_to_next_level();
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
            time_communicate += high_resolution_clock::now() - start_unit;
#endif
        }

#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
        auto end_compute = high_resolution_clock::now();
        time_active += end_compute - start;
#endif
        cout << "Client: receive aggregation from the server" << endl;
        read(*server_conn[PROT_MPC_SGX], buffer(msg_buf, 1));
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
        start_unit = high_resolution_clock::now();
#endif
        read(*server_conn[PROT_MPC_SGX], buffer(msg_buf + 1, ParamType::size()));
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
        auto duration_unit = high_resolution_clock::now() - start_unit;
        if (trust_ == Trust::NOT_TRUST()) {
            time_communicate += duration_unit;
        }
        else {
            cout << "Client: Total time for receiving inputs: " << 
                duration_cast<milliseconds>(duration_unit).count() << "ms." << endl;            
        }
#endif
#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
        auto start_receive = high_resolution_clock::now();
#endif
        check(msg_buf[0] == MSG_TYPE_OUTPUT);
#ifndef NDEBUG
        cout << "Client: got aggregated parameter " << ParamType::from_bytes(msg_buf + 1) << endl;
#endif

#if defined (PROT_MPC_TEST) || defined (SECAGG_TEST)
        auto end = high_resolution_clock::now();

        time_agg += end - start;
        time_active += end - start_receive;
        cout << "Client: Test complete. Total time for aggregation: " << 
            duration_cast<milliseconds>(time_agg).count() << "ms." << endl;
        cout << "Client: Test complete. Time for keeping active: " << 
            duration_cast<milliseconds>(time_active).count() << "ms." << endl;
        if (trust_ == Trust::NOT_TRUST()) {
            cout << "Client: Time for secagg communication: " << 
                duration_cast<milliseconds>(time_communicate).count() << "ms." << endl;
            cout << "Client: Time for secagg computation: " << 
                duration_cast<milliseconds>(time_compute).count() << "ms." << endl;
        }
#endif
    }

    ~ProtMPCClient() {
        mbedtls_ecdsa_free(&ecdsa);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        for (size_t i=0; i<N_TEE; ++i) {
            if (server_conn[i] != nullptr && server_conn[i]->is_open()) {
                server_conn[i]->close();
            }
        }
        for (size_t i=0; i<client_conn.size(); ++i) {
            if (client_conn[i] != nullptr && client_conn[i]->is_open()) {
                client_conn[i]->close();
            }
        }
        for (size_t i=0; i<N_TEE; ++i) {
            mbedtls_rsa_free(&rsa[i]);
            mbedtls_cipher_free(&symkey[i]);
        }
    }
};

int main(int argc, char *argv[]) {
    Args args = Args::parse(argc, argv);
    ProtMPCClient client(args.param, args.trust, args.config);

    try {
        client.run();
    } catch (const std::exception &e) {
        cout << e.what() << endl;
    }
}

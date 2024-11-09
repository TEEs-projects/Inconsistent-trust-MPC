// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <vector>
#include <string>
#include <sstream>
#include <string.h>
#include <string>

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
#include <string.h>

#include "prog_mpc.h"
#include "trace.h"

#include "secagg/zp.hpp"
#include "secagg/parameter.hpp"
#include "secagg/polynomial.hpp"
#include "secagg/common.h"

ProgMPCHandler::ProgMPCHandler(int n_prot_mpc_client, uint8_t *__pubkeys, size_t pubkeys_len)
    : n_prot_mpc_client(n_prot_mpc_client), commit_msg(n_prot_mpc_client) {
    check(pubkeys_len >= n_prot_mpc_client * ECDSA_PUB_KEY_SIZE);
    pubkeys = vector<mbedtls_ecdsa_context>(n_prot_mpc_client);
    symkey = vector<mbedtls_cipher_context_t>(n_prot_mpc_client);
    input_received = vector<char>(n_prot_mpc_client, false);

// TODO: recycle resources
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
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

    TRACE_ENCLAVE("prog_mpc: generate rsa key");
    mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, RSA_KEY_LEN, RSA_E);
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    mbedtls_ctr_drbg_random(&ctr_drbg, (unsigned char*)eid_.eid_, SECURITY_PARAMETER_SIZE);
#ifndef NDEBUG
    to_printable(eid_.eid_, SECURITY_PARAMETER_SIZE, msg_buf, MSG_BUF_SIZE);
    TRACE_ENCLAVE("generate eid: %s", (char*)msg_buf);
    fflush(stdout);
#endif

    // Initialize client public keys, this procedure is same as prog_bc
    // TODO: refactor
    TRACE_ENCLAVE("prog_mpc: initialize and read client public keys");
    mbedtls_ecp_group_init(&ECP_GROUP);
    mbedtls_ecp_group_load(&ECP_GROUP, ECDSA_GROUP);

    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    int ret;
    for (size_t i=0; i<n_prot_mpc_client; ++i) {
        ret = mbedtls_ecp_point_read_binary(
            &ECP_GROUP,
            &Q,
            __pubkeys + ECDSA_PUB_KEY_SIZE * i,
            ECDSA_PUB_KEY_SIZE
        );
        check(ret == 0);

        ret = mbedtls_ecp_group_load(&key.grp, ECDSA_GROUP);
        check(ret == 0);
        ret = mbedtls_ecp_copy(&key.Q, &Q);
        check(ret == 0);

        mbedtls_ecdsa_init(&pubkeys[i]);
        mbedtls_ecdsa_from_keypair(
            &pubkeys[i],
            &key
        );
    }

    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_point_free(&Q);

    // Initialize symmetric key contexts
    auto cipher_info = mbedtls_cipher_info_from_values(
        MBEDTLS_CIPHER_ID_AES,
        AES_KEY_LEN,
        MBEDTLS_MODE_CTR
    );
    check(cipher_info != nullptr);
    for (size_t i=0; i<n_prot_mpc_client; ++i) {
        mbedtls_cipher_init(&symkey[i]);
        ret = mbedtls_cipher_setup(&symkey[i], cipher_info);
        check(ret == 0);
    }
}

int ProgMPCHandler::get_random_polynomial_for_test(
    uint8_t *ret_buf,
    size_t *ret_len,
    size_t ret_buf_len
) {
    if (client) {
        stringstream ss;
        ss << client->get_random_polynomial_for_test();
        string str = ss.str();
        if (ret_buf_len < str.size()) {
            return MY_ECALL_FAILURE;
        }

        *ret_len = str.size();
        strcpy((char*)ret_buf, str.c_str());
    }
    else {
        ret_buf[0] = 0;
    }

    return MY_ECALL_SUCCESS;
}

int ProgMPCHandler::get_params_to(
    size_t id_in_group,
    uint8_t *param_buf,
    size_t param_len
) {
    static bool initialized = false;
    if (!initialized) {
        size_t n_client = N_TEE;
        for (size_t i=0; i<n_prot_mpc_client; ++i) {
            if (commit_msg.trust[i].need_input(PROT_MPC_SGX)) {
                check(input_received[i]);
            }
            else if (commit_msg.trust[i] == Trust::NOT_TRUST()) {
                ++n_client;
            }
        }
        secagg_config.reset(new SecaggConfig(n_client));
        client.reset(new Client(PROT_MPC_SGX, secagg_input, *secagg_config));
        group_member_received = vector<char>(secagg_config->group_size, false);
        TRACE_ENCLAVE("%u", (unsigned)group_member_received.size());
        initialized = true;
    }
    check(param_len == ParamType::size());
    if (id_in_group < secagg_config->group_size) {
        ParamType param = client->get_coded_params_to_group_member(id_in_group);
        param.to_bytes(param_buf);
    }
    else {
        for (size_t i=0; i<secagg_config->group_size; ++i) {
            check(group_member_received[i]);
        }
        if (client->group_info().group > 0) {
            check(prev_group_member_received);
        }
        ParamType param;
        if (client->group_info().group == secagg_config->n_group - 1) {
            param = client->get_local_aggregation_to_server();
        }
        else {
            param = client->get_aggregated_param_to_next_group_member();
        }
        param.to_bytes(param_buf);
    }

    return MY_ECALL_SUCCESS;
}

int ProgMPCHandler::set_params_from(
    size_t id_in_group,
    uint8_t *param_buf,
    size_t param_len
) {
    check(param_len == ParamType::size());
    ParamType param = ParamType::from_bytes(param_buf);

    if (id_in_group < secagg_config->group_size) {
        check(!group_member_received[id_in_group]);
        client->set_coded_params_from_group_member(id_in_group, param);
        group_member_received[id_in_group] = true;
    }
    else {
        check(!prev_group_member_received);
        client->set_aggregated_param_from_prev_group_member(param);
        prev_group_member_received = true;
    }

    return MY_ECALL_SUCCESS;
}

int ProgMPCHandler::key_gen(
    uint8_t *pubkey_buf,
    size_t *pubkey_len,
    size_t pubkey_buf_len,
    uint8_t *evidence_buf,
    size_t *evidence_len,
    size_t evidence_buf_len
) {
    static bool invoked = false;
    check(!invoked);
    invoked = true;

    size_t required_len = 1 + RSA_KEY_SIZE;
    check(pubkey_buf_len >= required_len);
    *pubkey_len = 1 + RSA_KEY_SIZE;
    pubkey_buf[0] = MSG_TYPE_SGX_PUBKEY;

    TRACE_ENCLAVE("prog_mpc: write public key");
    int ret;
    mbedtls_mpi N;
    mbedtls_mpi_init(&N);
    ret = mbedtls_rsa_export(&rsa, &N, nullptr, nullptr, nullptr, nullptr);
    check(ret == 0);
    ret = mbedtls_mpi_write_binary(&N, pubkey_buf + 1, RSA_KEY_SIZE);

    mbedtls_mpi_free(&N);

    TRACE_ENCLAVE("prog_mpc: generate evidence for public key");
    bool ok;
    uint8_t *evidence_in_enclave;
    size_t evidence_in_enclave_len;
    ok = evidence_generator.generate_attestation_evidence(
        pubkey_buf,
        required_len,
        &evidence_in_enclave,
        &evidence_in_enclave_len
    );
    check(ok);

    check(evidence_in_enclave_len <= evidence_buf_len);
    *evidence_len = evidence_in_enclave_len;
    memcpy(evidence_buf, evidence_in_enclave, evidence_in_enclave_len);

    evidence_generator.free_attestation_evidence(evidence_in_enclave);

    return MY_ECALL_SUCCESS;
}

int ProgMPCHandler::setup_input(
        uint8_t *input,
        size_t input_len,
        uint8_t *sig,
        size_t sig_len
) {
    // Parse input, see prot_mpc_client.cpp for format detials
    size_t fixed_len = 2 + 4 + RSA_KEY_SIZE
                            + AES_IV_SIZE 
                            + 4;
    check(input_len >= fixed_len);
    check(input[0] == MSG_TYPE_INPUT);
    check(input[1] < N_TEE);
    uint32_t client_id;
    ::from_bytes(input+2, &client_id);
    check(client_id < n_prot_mpc_client);

    // Verify signed message
    // TODO: refactor
    uint8_t hash[32];
    mbedtls_sha256_ret(input, input_len, hash, 0);

    int ret;
    ret = mbedtls_ecdsa_read_signature(
        &pubkeys[client_id],
        hash,
        32,
        sig,
        sig_len
    );
    check(ret == 0);

    uint8_t *ct_symkey = input + 2 + 4;
    uint8_t symkey_raw[AES_KEY_SIZE];
    size_t olen;
    ret = mbedtls_rsa_rsaes_oaep_decrypt(
        &rsa,
        mbedtls_ctr_drbg_random,
        &ctr_drbg,
        MBEDTLS_RSA_PRIVATE,
        nullptr,
        0,
        &olen,
        ct_symkey,
        symkey_raw,
        AES_KEY_SIZE
    );
    check(ret == 0);
    check(olen == AES_KEY_SIZE);
#ifndef NDEBUG
    to_printable(symkey_raw, AES_KEY_SIZE, msg_buf, MSG_BUF_SIZE);
    TRACE_ENCLAVE("decrypt symkey: %s", msg_buf);
#endif

    check(!input_received[client_id]);
    TRACE_ENCLAVE("client_id: %u, trust: %u", client_id, commit_msg.trust[client_id].j_);
    check(commit_msg.trust[client_id].need_input(PROT_MPC_SGX));

    mbedtls_cipher_setkey(
        &symkey[client_id],
        symkey_raw,
        AES_KEY_LEN,
        MBEDTLS_ENCRYPT
    );

    uint8_t *iv = ct_symkey + RSA_KEY_SIZE,
            *ct_len_raw = iv + AES_IV_SIZE,
            *ct = ct_len_raw + 4;
    uint32_t ct_len;
    ::from_bytes(ct_len_raw, &ct_len);

    check( fixed_len + ct_len <= input_len );

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
    to_printable(param_buf, pt_len, msg_buf, MSG_BUF_SIZE);
    TRACE_ENCLAVE("decrypt parameter: %s", (char*)msg_buf);
#endif

    ParamType param = ParamType::from_bytes(param_buf);
    secagg_input = secagg_input + param;
    input_received[client_id] = true;

    return MY_ECALL_SUCCESS;
}

int ProgMPCHandler::test_attestation(
        uint8_t *out_buf,
        size_t out_buf_len,
        uint8_t *evidence_buf,
        size_t *evidence_len,
        size_t evidence_buf_len
) {
    bool ok;
    int ret;

    const char to_be_attested[] = "test";
    uint8_t *evidence_in_enclave_buf;
    size_t evidence_in_enclave_len;
    ok = evidence_generator.generate_attestation_evidence(
        (const uint8_t *)to_be_attested,
        strlen(to_be_attested),
        &evidence_in_enclave_buf,
        &evidence_in_enclave_len
    );
    check(ok);

    if (evidence_in_enclave_len > evidence_buf_len) {
        TRACE_ENCLAVE("not enough buffer to hold evidence, required: %lu, actual: %lu", evidence_in_enclave_len, evidence_buf_len);
        oe_free_evidence(evidence_in_enclave_buf);
        return MY_ECALL_FAILURE;
    }

    memcpy(evidence_buf, evidence_in_enclave_buf, evidence_in_enclave_len);
    *evidence_len = evidence_in_enclave_len;

    oe_free_evidence(evidence_in_enclave_buf);
    return MY_ECALL_SUCCESS;
}

int ProgMPCHandler::setup_commit_msg(
    uint8_t *commit_msg,
    size_t msg_len,
    uint8_t *evidence,
    size_t evidence_len
) {
    // TODO: check MRENCLAVE
    bool ok = evidence_verifier.verify_evidence(
        &sgx_remote_uuid, evidence, evidence_len, commit_msg, msg_len
    );
    check(ok);
    check(commit_msg[0] == MSG_TYPE_COMMIT);

    CommitMessage::from_bytes(commit_msg + 1, msg_len - 1, n_prot_mpc_client, &this->commit_msg);
#ifndef NDEBUG
    to_printable(this->commit_msg.eid[PROT_MPC_SGX].eid_, SECURITY_PARAMETER_SIZE, msg_buf, MSG_BUF_SIZE);
    TRACE_ENCLAVE("received eid: %s", (char*)msg_buf);
    fflush(stdout);
    to_printable(eid_.eid_, SECURITY_PARAMETER_SIZE, msg_buf, MSG_BUF_SIZE);
    TRACE_ENCLAVE("generated: %s", (char*)msg_buf);
    fflush(stdout);
#endif
    check(this->commit_msg.eid[PROT_MPC_SGX] == eid_);

    return MY_ECALL_SUCCESS;
}

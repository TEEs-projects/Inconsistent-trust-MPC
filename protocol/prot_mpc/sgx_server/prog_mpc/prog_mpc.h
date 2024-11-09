// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
#include <mbedtls/rsa.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ecdsa.h>
#include <openenclave/enclave.h>
#include <string>
#include <vector>

#include "constant.h"
#include "secagg/client.hpp"
#include "secagg/common.h"
#include "trace.h"

#include "evidence_generator.h"
#include "evidence_verifier.h"

using namespace std;

class ProgMPCHandler {
private:
    size_t n_prot_mpc_client;

// TODO: recycle resources
    unique_ptr<Client> client;
    ParamType secagg_input = ParamType(0);
    unique_ptr<SecaggConfig> secagg_config;

    CommitMessage commit_msg;

    EvidenceGenrator evidence_generator;
    EvidenceVerifier evidence_verifier;

    mbedtls_ecp_group ECP_GROUP;
    vector<mbedtls_ecdsa_context> pubkeys;

    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    vector<mbedtls_cipher_context_t> symkey;

    vector<char> input_received;
    vector<char> group_member_received;
    bool prev_group_member_received = false;

    static constexpr size_t MSG_BUF_SIZE = 1024 * 1024 * 10;
    uint8_t *msg_buf = new uint8_t[MSG_BUF_SIZE];

public:
    EID eid_;

    ProgMPCHandler(int n_prot_mpc_client, uint8_t *__pubkeys, size_t pubkeys_len);

    int get_random_polynomial_for_test(
        uint8_t *ret_buf,
        size_t *ret_len,
        size_t ret_buf_len
    );

    int get_params_to(
        size_t id_in_group,
        uint8_t *param_buf,
        size_t param_len
    );

    int set_params_from(
        size_t id_in_group,
        uint8_t *param_buf,
        size_t param_len
    );

    int key_gen(
        uint8_t *pubkey_buf,
        size_t *pubkey_len,
        size_t pubkey_buf_len,
        uint8_t *evidence_buf,
        size_t *evidence_len,
        size_t evidence_buf_len
    );

    int setup_commit_msg(
        uint8_t *commit_msg,
        size_t msg_len,
        uint8_t *evidence,
        size_t evidence_len
    );

    int setup_input(
        uint8_t *input,
        size_t input_len,
        uint8_t *sig,
        size_t sig_len
    );

    int test_attestation(
        uint8_t *out_buf,
        size_t out_buf_len,
        uint8_t *evidence_buf,
        size_t *evidence_len,
        size_t evidence_buf_len
    );
};

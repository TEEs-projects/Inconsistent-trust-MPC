// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <openenclave/enclave.h>
#include <string>
#include <vector>

#include "check.h"
#include "trace.h"
#include "constant.h"
#include "evidence_generator.h"
#include "evidence_verifier.h"

using namespace std;

class ProgBcHandler {
private:
    size_t n_prot_mpc_client;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecp_group ECP_GROUP;
    vector<mbedtls_ecdsa_context> pubkeys;

    CommitMessage commit_msg;

    EvidenceGenrator evidence_generator;
    EvidenceVerifier evidence_verifier;

    static constexpr size_t MSG_BUF_SIZE = 1024;
    uint8_t msg_buf[MSG_BUF_SIZE];

public:
    const EID eid_;

    ProgBcHandler(int n_prot_mpc_client, uint8_t *__pubkeys, size_t pubkeys_len);

    int setup(
        uint8_t *sig,
        size_t sig_len,
        uint8_t *msg,
        size_t msg_len
    );

    int key_setup(
        uint8_t *eid,
        size_t eid_len,
        uint8_t *evidence,
        size_t evidence_len,
        int tee_id,
        uint8_t *pk_priv,
        size_t pk_priv_len
    );

    int commit(
        uint8_t *ret_buf,
        size_t *ret_len,
        size_t ret_buf_len,
        uint8_t *evidence_buf,
        size_t *evidence_len,
        size_t evidence_buf_len
    );
};

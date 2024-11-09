// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>
#include <string.h>

#include <sstream>

#include "prog_bc.h"
#include "trace.h"

#include "constant.h"

ProgBcHandler::ProgBcHandler(int n_prot_mpc_client, uint8_t *__pubkeys, size_t pubkeys_len)
: n_prot_mpc_client(n_prot_mpc_client), commit_msg(n_prot_mpc_client) {
    check(pubkeys_len >= n_prot_mpc_client * ECDSA_PUB_KEY_SIZE);
    pubkeys = vector<mbedtls_ecdsa_context>(n_prot_mpc_client);
    // TODO: recycle resources
    int ret;

    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_init(&entropy);
    const char pers[] = "pers";
    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func,
        &entropy,
        (const unsigned char *)pers,
        strlen(pers)
    );
    check(ret == 0);

    mbedtls_ctr_drbg_random(&ctr_drbg, (unsigned char*)eid_.eid_, SECURITY_PARAMETER_SIZE);
    commit_msg.eid_bc = eid_;

    TRACE_ENCLAVE("prog_bc: initialize and read client public keys");
    mbedtls_ecp_group_init(&ECP_GROUP);
    mbedtls_ecp_group_load(&ECP_GROUP, ECDSA_GROUP);

    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
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
}

int ProgBcHandler::setup(
    uint8_t *sig,
    size_t sig_len,
    uint8_t *msg,
    size_t msg_len
) {
    check(msg_len >= AckMessage::size() + 1);
    check(msg[0] == MSG_TYPE_ACK);
    AckMessage ack_msg;
    AckMessage::from_bytes(msg + 1, &ack_msg);
#ifndef NDEBUG
    TRACE_ENCLAVE("prog_bc: receive ack_msg. id: %u, trust: %u", ack_msg.client_id, ack_msg.trust.j_);
#endif
    check(ack_msg.client_id < n_prot_mpc_client);
    check(ack_msg.trust.is_valid());

    int ret;

    uint8_t hash[32];
    mbedtls_sha256_ret(msg, msg_len, hash, 0);

#ifndef NDEBUG
    TRACE_ENCLAVE("prog_bc: verify signature");
#endif
    ret = mbedtls_ecdsa_read_signature(
        &pubkeys[ack_msg.client_id],
        hash,
        32,
        sig,
        sig_len
    );
    if (ret != 0) {
        TRACE_ENCLAVE("signature verification failed: returned %d", ret);
        mbedtls_strerror(ret, (char*)msg_buf, MSG_BUF_SIZE);
        TRACE_ENCLAVE("%s", (char*)msg_buf);
        check(0);
    }

    check(eid_ == ack_msg.eid_bc);

    check(commit_msg.trust[ack_msg.client_id] == Trust::UNSET());
    commit_msg.trust[ack_msg.client_id] = ack_msg.trust;

    return MY_ECALL_SUCCESS;
}

int ProgBcHandler::key_setup(
    uint8_t *eid,
    size_t eid_len,
    uint8_t *evidence,
    size_t evidence_len,
    int tee_id,
    uint8_t *pk_priv,
    size_t pk_priv_len
) {
    size_t expected_len = 1 + RSA_KEY_SIZE;
    check(pk_priv_len == expected_len);
    check(eid_len == SECURITY_PARAMETER_SIZE);
    check(tee_id < N_TEE);

    if (tee_id == PROT_MPC_SGX) {
        check(pk_priv[0] == MSG_TYPE_SGX_PUBKEY);
        bool ok = false;
        ok = evidence_verifier.verify_evidence(
            &sgx_remote_uuid,
            evidence,
            evidence_len,
            pk_priv,
            pk_priv_len
        );
        check(ok);
    }
    else if (tee_id == PROT_MPC_AMD) {
        check(pk_priv[0] == MSG_TYPE_AMD_PUBKEY);
        // TODO
    }

    check(commit_msg.pk[tee_id].empty());
    commit_msg.pk[tee_id] = vector<uint8_t>(pk_priv+1, pk_priv+1+RSA_KEY_SIZE);
    EID::from_bytes(eid, &commit_msg.eid[tee_id]);
#ifndef NDEBUG
    to_printable(eid, SECURITY_PARAMETER_SIZE, msg_buf, MSG_BUF_SIZE);
    TRACE_ENCLAVE("received eid: %s", (char*)msg_buf);
    fflush(stdout);
#endif

    return MY_ECALL_SUCCESS;
}

int ProgBcHandler::commit(
    uint8_t *ret_buf,
    size_t *ret_len,
    size_t ret_buf_len,
    uint8_t *evidence_buf,
    size_t *evidence_len,
    size_t evidence_buf_len
) {
    for (size_t i=0; i<N_TEE; ++i) {
        check(!commit_msg.pk[i].empty());
    }
    for (size_t i=0; i<n_prot_mpc_client; ++i) {
        check(commit_msg.trust[i] != Trust::UNSET());
    }

    *ret_buf = MSG_TYPE_COMMIT;
    uint8_t *end = commit_msg.to_bytes(ret_buf + 1, ret_buf_len - 1);

    *ret_len = end - ret_buf;

#ifndef NDEBUG
    to_printable(this->commit_msg.eid[PROT_MPC_SGX].eid_, SECURITY_PARAMETER_SIZE, msg_buf, MSG_BUF_SIZE);
    TRACE_ENCLAVE("SGX eid: %s", (char*)msg_buf);
    fflush(stdout);
#endif

    uint8_t *evidence = nullptr;
    bool ok = evidence_generator.generate_attestation_evidence(
        ret_buf,
        *ret_len,
        &evidence,
        evidence_len
    );
    check(ok);
    check(*evidence_len <= evidence_buf_len);

    memcpy(evidence_buf, evidence, *evidence_len);
    evidence_generator.free_attestation_evidence(evidence);

    return MY_ECALL_SUCCESS;
}

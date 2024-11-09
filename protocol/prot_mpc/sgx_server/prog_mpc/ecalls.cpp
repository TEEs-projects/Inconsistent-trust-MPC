// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <string.h>

#include <openenclave/enclave.h>
#include <memory>

#include "prog_mpc.h"
#include "prog_mpc_t.h"

#include "constant.h"

std::unique_ptr<ProgMPCHandler> prog_mpc_handler;

size_t n_prot_mpc_client = 0;

// Load public configs, including the number of clients and clients' public keys.
// Having the enclaves loading configs is for convinience. This is insecure.
// To load the config at compiling time, see common/key_gen.cpp and corresponding CMake files.
int prog_mpc_load_config(
    size_t n_prot_mpc_client,
    uint8_t *pubkeys,
    size_t pubkeys_len
) {
    prog_mpc_handler.reset(new ProgMPCHandler(n_prot_mpc_client, pubkeys, pubkeys_len));
#ifndef NDEBUG
    char msg_buf[2*SECURITY_PARAMETER_SIZE + 1];
    to_printable(prog_mpc_handler->eid_.eid_, SECURITY_PARAMETER_SIZE, (uint8_t*)msg_buf, 2*SECURITY_PARAMETER_SIZE + 1);
    TRACE_ENCLAVE("get eid: %s", (char*)msg_buf);
    fflush(stdout);
#endif

    return MY_ECALL_SUCCESS;
}

int get_prog_mpc_eid(uint8_t *ret_buf, size_t ret_buf_len) {
    check(ret_buf_len == SECURITY_PARAMETER_SIZE);
    prog_mpc_handler->eid_.to_bytes(ret_buf);
#ifndef NDEBUG
    char msg_buf[2*SECURITY_PARAMETER_SIZE + 1];
    to_printable(prog_mpc_handler->eid_.eid_, SECURITY_PARAMETER_SIZE, (uint8_t*)msg_buf, 2*SECURITY_PARAMETER_SIZE + 1);
    TRACE_ENCLAVE("get eid: %s", (char*)msg_buf);
    fflush(stdout);
#endif

    return MY_ECALL_SUCCESS;
}

int get_random_polynomial_for_test(
    uint8_t *ret_buf,
    size_t *ret_len,
    size_t ret_buf_len
) {
    return prog_mpc_handler->get_random_polynomial_for_test(ret_buf, ret_len, ret_buf_len);
}

int get_params_to(
    size_t id_in_group, // If id_in_group < GROUP_SIZE, returns the parameter sent to group member.
                        // Otherwise, returns the parameter sent to the next group member
    uint8_t *param,
    size_t param_len
) {
    return prog_mpc_handler->get_params_to(id_in_group, param, param_len);
}

int set_params_from(
    size_t id_in_group, // If id_in_group < GROUP_SIZE, set the parameter to group member.
                        // Otherwise, set the parameter from the last group
    uint8_t *param,
    size_t param_len
) {
    return prog_mpc_handler->set_params_from(id_in_group, param, param_len);
}

int key_gen(
    uint8_t *pubkey_buf,
    size_t *pubkey_len,
    size_t pubkey_buf_len,
    uint8_t *evidence_buf,
    size_t *evidence_len,
    size_t evidence_buf_len
) {
    return prog_mpc_handler->key_gen(pubkey_buf, pubkey_len, pubkey_buf_len, evidence_buf, evidence_len, evidence_buf_len);
}

int setup_input(
    uint8_t *input,
    size_t input_len,
    uint8_t *sig,
    size_t sig_len
) {
    return prog_mpc_handler->setup_input(
        input, input_len, sig, sig_len
    );
}

int setup_commit_msg(
    uint8_t *commit_msg,
    size_t msg_len,
    uint8_t *evidence,
    size_t evidence_len
) {
    return prog_mpc_handler->setup_commit_msg(
        commit_msg, msg_len, evidence, evidence_len
    );
}

int test_attestation(
    uint8_t *out_buf,
    size_t out_buf_len,
    uint8_t *evidence_buf,
    size_t *evidence_len,
    size_t evidence_buf_len
) {
    return prog_mpc_handler->test_attestation(
        out_buf, out_buf_len, evidence_buf, evidence_len, evidence_buf_len
    );
}

// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <vector>
#include <memory>

#include "prog_bc.h"
#include "prog_bc_t.h"

#include "constant.h"

static std::unique_ptr<ProgBcHandler> prog_bc_handler;

int custom_ecall()
{
    return 114514;
}

// Load public configs, including the number of clients and clients' public keys.
// Having the enclaves loading configs during running is just for convenience
// when testing and is essentially insecure.
// To load the config at compiling time, see common/key_gen.cpp and corresponding
// CMake files.
int prog_bc_load_config(
    size_t n_prot_mpc_client,
    uint8_t *pubkeys,
    size_t pubkeys_len
) {
    prog_bc_handler.reset(new ProgBcHandler(n_prot_mpc_client, pubkeys, pubkeys_len));

    return MY_ECALL_SUCCESS;
}

int get_prog_bc_eid(uint8_t *ret_buf, size_t ret_buf_len) {
    assert(ret_buf_len == SECURITY_PARAMETER_SIZE);
    prog_bc_handler->eid_.to_bytes(ret_buf);

    return MY_ECALL_SUCCESS;
}

int setup(
    uint8_t *sig,
    size_t sig_len,
    uint8_t *msg,
    size_t msg_len
) {
    return prog_bc_handler->setup(sig, sig_len, msg, msg_len);
}

int key_setup(
    uint8_t *eid,
    size_t eid_len,
    uint8_t *evidence,
    size_t evidence_len,
    int tee_id,
    uint8_t *pk_priv,
    size_t pk_priv_len
) {
    return prog_bc_handler->key_setup(eid, eid_len, evidence, evidence_len, tee_id, pk_priv, pk_priv_len);
}

int commit(
    uint8_t *ret_buf,
    size_t *ret_len,
    size_t ret_buf_len,
    uint8_t *evidence_buf,
    size_t *evidence_len,
    size_t evidence_buf_len
) {
    return prog_bc_handler->commit(ret_buf, ret_len, ret_buf_len, evidence_buf, evidence_len, evidence_buf_len);
}

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>


#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>

#include "check.h"
#include "constant.h"

#include <nlohmann/json.hpp>

using namespace std;
using namespace nlohmann;

int main(int argc, char *argv[]) {
    check(argc >= 3);
    fstream f(argv[1]);
    json json_config = json::parse(f);

    int n_prot_mpc_client = json_config["client"]["n_prot_mpc_client"];

    int ret = 1;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    cout << "init entropy and ctr_drbg" << endl;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func,
        &entropy,
        (const unsigned char *) pers,
        strlen(pers)
    );
    check(ret == 0);

    cout << "generate keys" << endl;
    vector<mbedtls_ecp_keypair> keys(n_prot_mpc_client);
    for (size_t i=0; i<n_prot_mpc_client; ++i) {
        mbedtls_ecp_keypair_init(&keys[i]);
        ret = mbedtls_ecp_gen_key(
            ECDSA_GROUP,
            &keys[i],
            mbedtls_ctr_drbg_random,
            &ctr_drbg
        );
        check(ret == 0);
    }

    constexpr size_t buf_size = 1024;
    uint8_t key_buf[buf_size];
    size_t key_len = 0;

    cout << "write private keys and public keys" << endl;
    fstream key_file("./privkeys", ios::out | ios::binary);
    fstream pubkey_file(argv[2], ios::out);
    pubkey_file << "static unsigned char __pubkeys[] = {\n";
    for (size_t i=0; i<n_prot_mpc_client; ++i) {
        ret = mbedtls_ecp_write_key_ext(
            &keys[i],
            &key_len,
            key_buf,
            buf_size
        );
        check(ret == 0);
        check(key_len == ECDSA_PRIV_KEY_SIZE);
        key_file.write((const char*)key_buf, key_len);

        ret = mbedtls_ecp_write_public_key(
            &keys[i],
            MBEDTLS_ECP_PF_UNCOMPRESSED,
            &key_len,
            key_buf,
            buf_size
        );
        check(ret == 0);
        check(key_len == ECDSA_PUB_KEY_SIZE);

        for (size_t i=0; i<key_len; ++i) {
            pubkey_file << (int)key_buf[i] << ", ";
        }
    }
    pubkey_file << "0\n};\n";
    pubkey_file << "#define N_PROT_MPC_CLIENT " << n_prot_mpc_client;

    key_file.close();
    pubkey_file.close();
}
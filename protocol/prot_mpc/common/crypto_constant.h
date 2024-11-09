#pragma once

// Remember to update the annotations
// of messages if the following macros are updated
#define ECDSA_PRIV_KEY_SIZE 32
#define ECDSA_PUB_KEY_SIZE 65
#define ECDSA_GROUP MBEDTLS_ECP_DP_SECP256R1

#define RSA_KEY_LEN 2048
#define RSA_KEY_SIZE (RSA_KEY_LEN/8)
#define RSA_E 65537

#define AES_KEY_LEN 128
#define AES_KEY_SIZE (AES_KEY_LEN/8)
#define AES_IV_LEN 128
#define AES_IV_SIZE (AES_IV_LEN/8)
#define AES_BLOCK_SIZE 16
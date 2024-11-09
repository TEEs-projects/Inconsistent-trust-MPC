// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <string.h>
#include <openssl/sha.h>

#include "trace.h"
#include "check.h"
#include "evidence_verifier.h"

EvidenceVerifier::EvidenceVerifier()
{
    int ret = oe_verifier_initialize();
    check(ret == OE_OK);
}

// !!!!! NOTE: verify is_in_enclave is disabled.
// If veirification is completed in the enclave, evidence should be copied into secure memory

/**
 * Attest the given evidence and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The evidence is first attested using the oe_verify_evidence API.
 * This ensures the authenticity of the enclave that generated the evidence.
 * 2) Next, to establish trust in the enclave that generated the
 * evidence, the signer_id, product_id, and security version values are
 * checked to see if they are predefined trusted values.
 * 3) Once the enclave's trust has been established,
 * the validity of accompanying data is ensured by comparing its SHA256 digest
 * against the OE_CLAIM_CUSTOM_CLAIMS_BUFFER claim.
 */
bool EvidenceVerifier::verify_evidence(
    const oe_uuid_t* format_id,
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* data,
    size_t data_size)
{
    bool ret = false;
    uint8_t hash[32];
    oe_result_t result = OE_OK;
    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;
    const oe_claim_t* claim;
    oe_claim_t* custom_claims = nullptr;
    size_t custom_claims_length = 0;

    // 1) Validate the evidence's trustworthiness
    // Verify the evidence to ensure its authenticity.
    result = oe_verify_evidence(
        format_id,
        evidence,
        evidence_size,
        nullptr,
        0,
        nullptr,
        0,
        &claims,
        &claims_length);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE(
            "oe_verify_evidence failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    TRACE_ENCLAVE("oe_verify_evidence succeeded");

    // 2) validate the enclave identity's signer_id is the hash of the public
    // signing key that was used to sign an enclave. Check that the enclave was
    // signed by an trusted entity.

    // Validate the signer id.
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID)) ==
        nullptr)
    {
        TRACE_ENCLAVE("Could not find claim.");
        goto exit;
    };

    if (claim->value_size != OE_SIGNER_ID_SIZE)
    {
        TRACE_ENCLAVE("signer_id size(%lu) checking failed", claim->value_size);
        goto exit;
    }

    // Check the enclave's product id.
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_PRODUCT_ID)) ==
        nullptr)
    {
        TRACE_ENCLAVE("could not find claim");
        goto exit;
    };

    if (claim->value_size != OE_PRODUCT_ID_SIZE)
    {
        TRACE_ENCLAVE(
            "product_id size(%lu) checking failed", claim->value_size);
        goto exit;
    }

    if (*(claim->value) != 1)
    {
        TRACE_ENCLAVE("product_id(%u) checking failed", *(claim->value));
        goto exit;
    }

    // Check the enclave's security version.
    if ((claim = _find_claim(
             claims, claims_length, OE_CLAIM_SECURITY_VERSION)) == nullptr)
    {
        TRACE_ENCLAVE("could not find claim");
        goto exit;
    };

    if (claim->value_size != sizeof(uint32_t))
    {
        TRACE_ENCLAVE(
            "security_version size(%lu) checking failed", claim->value_size);
        goto exit;
    }

    if (*(claim->value) < 1)
    {
        TRACE_ENCLAVE("security_version(%u) checking failed", *(claim->value));
        goto exit;
    }

    // 3) Validate the custom claims buffer
    //    Deserialize the custom claims buffer to custom claims list, then fetch
    //    the hash value of the data held in custom_claims[1].
    if ((claim = _find_claim(
             claims, claims_length, OE_CLAIM_CUSTOM_CLAIMS_BUFFER)) == nullptr)
    {
        TRACE_ENCLAVE("Could not find claim.");
        goto exit;
    }

    SHA256(data, data_size, hash);

    // deserialize the custom claims buffer
#ifndef NDEBUG
    TRACE_ENCLAVE("oe_deserialize_custom_claims");
#endif
    if (oe_deserialize_custom_claims(
            claim->value,
            claim->value_size,
            &custom_claims,
            &custom_claims_length) != OE_OK)
    {
        TRACE_ENCLAVE("oe_deserialize_custom_claims failed.");
        goto exit;
    }

#ifndef NDEBUG
    TRACE_ENCLAVE(
        "custom claim 1(%s): %s",
        custom_claims[0].name,
        custom_claims[0].value);

    TRACE_ENCLAVE("custom claim 2(%s) hash check:", custom_claims[1].name);
#endif

    if (custom_claims[1].value_size != sizeof(hash) ||
        memcmp(custom_claims[1].value, hash, sizeof(hash)) != 0)
    {
        TRACE_ENCLAVE("hash mismatch");
        goto exit;
    }
#ifndef NDEBUG
    TRACE_ENCLAVE("hash match");
#endif

    ret = true;
    TRACE_ENCLAVE("attestation succeeded");
exit:
    oe_free_claims(claims, claims_length);
    return ret;
}

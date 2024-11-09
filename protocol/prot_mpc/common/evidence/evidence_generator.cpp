// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/bits/report.h>
#include <mbedtls/sha256.h>
#include <string.h>

#include "trace.h"
#include "evidence_generator.h"
#include "evidence_common.h"

EvidenceGenrator::EvidenceGenrator()
{
    // This leaks the memory to store format settings
    // TODO: recycle resources
    get_format_settings(&sgx_remote_uuid, &format_settings, &format_settings_size);
}

/**
 * Get format settings for the given enclave.
 */
bool EvidenceGenrator::get_format_settings(
    const oe_uuid_t* format_id,
    uint8_t** format_settings,
    size_t* format_settings_size)
{
    bool ret = false;

    // Intialize verifier to get enclave's format settings.
    if (oe_verifier_initialize() != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_initialize failed");
        goto exit;
    }

    // Use the plugin.
    if (oe_verifier_get_format_settings(
            format_id, format_settings, format_settings_size) != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_get_format_settings failed");
        goto exit;
    }
    ret = true;

exit:
    return ret;
}

void EvidenceGenrator::free_attestation_evidence(uint8_t *evidence)
{
    oe_free_evidence(evidence);
}

/**
 * Generate evidence for the given data.
 */
bool EvidenceGenrator::generate_attestation_evidence(
    const uint8_t* data,
    const size_t data_size,
    uint8_t** evidence,
    size_t* evidence_size)
{
    bool ret = false;
    uint8_t hash[32];
    oe_result_t result = OE_OK;
    uint8_t* custom_claims_buffer = nullptr;
    size_t custom_claims_buffer_size = 0;
    char custom_claim1_name[] = "Event";
    char custom_claim1_value[] = "Attestation sample";
    char custom_claim2_name[] = "Public key hash";

    // The custom_claims[1].value will be filled with hash of public key later
    oe_claim_t custom_claims[2] = {
        {.name = custom_claim1_name,
         .value = (uint8_t*)custom_claim1_value,
         .value_size = sizeof(custom_claim1_value)},
        {.name = custom_claim2_name, .value = nullptr, .value_size = 0}};

    mbedtls_sha256_ret(data, data_size, hash, 0);

    // Initialize attester and use the plugin.
    result = oe_attester_initialize();
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_attester_initialize failed.");
        goto exit;
    }

    // serialize the custom claims, store hash of data in custom_claims[1].value
    custom_claims[1].value = hash;
    custom_claims[1].value_size = sizeof(hash);

#ifndef NDEBUG
    TRACE_ENCLAVE("oe_serialize_custom_claims");
#endif
    if (oe_serialize_custom_claims(
            custom_claims,
            2,
            &custom_claims_buffer,
            &custom_claims_buffer_size) != OE_OK)
    {
        TRACE_ENCLAVE("oe_serialize_custom_claims failed.");
        goto exit;
    }
#ifndef NDEBUG
    TRACE_ENCLAVE(
        "serialized custom claims buffer size: %lu", custom_claims_buffer_size);
#endif

    // Generate evidence based on the format selected by the attester.
    result = oe_get_evidence(
        &sgx_remote_uuid,
        0,
        custom_claims_buffer,
        custom_claims_buffer_size,
        format_settings,
        format_settings_size,
        evidence,
        evidence_size,
        nullptr,
        0);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_evidence failed.(%s)", oe_result_str(result));
        goto exit;
    }

    ret = true;
    TRACE_ENCLAVE("generate_attestation_evidence succeeded.");
exit:
    return ret;
}



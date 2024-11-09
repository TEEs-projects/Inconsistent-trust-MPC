// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef EVIDENCE_GENERATOR_H
#define EVIDENCE_GENERATOR_H

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>
#include <openenclave/attestation/sgx/evidence.h>

class EvidenceGenrator
{
  private:
    uint8_t *format_settings;
    size_t format_settings_size;

    // Get format settings.
    bool get_format_settings(
        const oe_uuid_t* format_id,
        uint8_t** format_settings_buffer,
        size_t* format_settings_buffer_size);

  public:
    EvidenceGenrator();

    // Generate evidence for the given data.
    bool generate_attestation_evidence(
        const uint8_t* data,
        size_t data_size,
        uint8_t** evidence,
        size_t* evidence_size);

    void free_attestation_evidence(uint8_t *evidence);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H

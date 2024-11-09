// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef EVIDENCE_VERIFIER_H
#define EVIDENCE_VERIFIER_H

#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/enclave.h>

#include "evidence_common.h"

class EvidenceVerifier
{
  private:

  public:
    EvidenceVerifier();

    /**
     * Attest the given evidence and accompanying data. The evidence
     * is first attested using the oe_verify_evidence API. This ensures the
     * authenticity of the enclave that generated the evidence. Next the enclave
     * signer_id and unique_id values are tested to establish trust of the
     * enclave that generated the evidence.
     */
    bool verify_evidence(
        const oe_uuid_t* format_id,
        const uint8_t* evidence,
        size_t evidence_size,
        const uint8_t* data,
        size_t data_size);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H

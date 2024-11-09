#pragma once

#include <memory.h>
#include <limits.h>
#include <stdint.h>
#include <vector>
#include <unordered_map>
#include <utility>
#include <mbedtls/ecp.h>

#include <stdio.h>

#include "crypto_constant.h"
#include "check.h"
#include "secagg/common.h"

#define N_TEE 2
// The max number of clients. This is limited by the number of pre-generated keys.
#define MAX_N_PROT_MPC_CLIENT 2000

static_assert(N_TEE <= 2, "Too many TEEs, currently only SGX and AMD-SEV are supported");
static_assert(N_TEE < 0xff, "Too many TEEs");

#define PROT_MPC_SGX 0
#define PROT_MPC_AMD 1

#define ADV_NOT_TRUST 0
#define ADV_PARTIAL_TRUST 1
#define ADV_UNSET -1

inline int adv_complete_trust(int j) { return (ADV_PARTIAL_TRUST + 1 + j); }
inline int tee(int j) { return j - ADV_PARTIAL_TRUST - 1; }

#define ADV_COMPLETE_TRUST(j) (::adv_complete_trust(j))

inline uint8_t *to_bytes(uint8_t *buf, uint32_t val) {
    // little endian
    uint8_t *end = buf+sizeof(val);
    for (uint8_t *cur = buf; cur != end; ++cur) {
        *cur = val & 0xff;
        val >>= 8;
    }
    return end;
}

inline const uint8_t *from_bytes(const uint8_t *buf, uint32_t *val) {
    *val = 0;
    const uint8_t *beg = buf+sizeof(*val)-1;
    for (const uint8_t *cur = beg; cur != buf-1; --cur) {
        *val <<= 8;
        *val |= *cur;
    }
    return beg + 1;
}

inline uint8_t *append_to_buf(uint8_t *buf, const char *msg, size_t msg_len) {
    static_assert(CHAR_BIT == 8, "CHAR_BIT not equals to 8");
    memcpy(buf, msg, msg_len);
    return buf + msg_len;
}

inline const uint8_t *read_from_buf(const uint8_t *buf, char *msg_buf, size_t msg_len) {
    memcpy(msg_buf, buf, msg_len);
    return buf + msg_len;
}

struct Trust {
    uint32_t j_ = ADV_UNSET;

    Trust() = default;
    Trust(const Trust &trust) = default;
    Trust &operator=(const Trust &trust) = default;
    explicit Trust(uint32_t trust): j_(trust) { check(trust <= ADV_COMPLETE_TRUST(N_TEE-1) || trust == ADV_UNSET); }

    bool operator==(const Trust &o) const { return j_ == o.j_; }
    bool operator!=(const Trust &o) const { return !(*this == o); }

    uint8_t *to_bytes(uint8_t *buf) const {
        return ::to_bytes(buf, j_);
    }

    bool is_complete_trust() const { return j_ >= ADV_COMPLETE_TRUST(0); }

    bool is_valid() const { return j_ <= ADV_COMPLETE_TRUST(N_TEE-1); }

    bool need_input(size_t tee_id) const {
        return *this == Trust::PARTIAL_TRUST() || *this == Trust::COMPLETE_TRUST(tee_id);
    }

    size_t tee() const {
        check(j_>=ADV_COMPLETE_TRUST(0) && j_<=ADV_COMPLETE_TRUST(N_TEE-1));
        return ::tee(j_);
    }

    static const uint8_t *from_bytes(const uint8_t *buf, Trust *trust) {
        return ::from_bytes(buf, &trust->j_);
    }

    static constexpr size_t size() { return sizeof(j_); }

    static Trust UNSET() { return Trust(ADV_UNSET); }
    static Trust NOT_TRUST() { return Trust(ADV_NOT_TRUST); }
    static Trust PARTIAL_TRUST() { return Trust(ADV_PARTIAL_TRUST); }
    static Trust COMPLETE_TRUST(uint32_t i) { check(i>=0 && i<N_TEE); return Trust(ADV_COMPLETE_TRUST(i)); }
};

#define SECURITY_PARAMETER 128

#define SECURITY_PARAMETER_SIZE (SECURITY_PARAMETER / 8)

#define MSG_TYPE_EID 0
#define MSG_TYPE_ACK 1
#define MSG_TYPE_COMMIT 2
#define MSG_TYPE_KEY_SETUP 3
#define MSG_TYPE_SGX_PUBKEY 4
#define MSG_TYPE_AMD_PUBKEY 5
#define MSG_TYPE_INPUT 6
#define MSG_TYPE_SECAGG 7
#define MSG_TYPE_OUTPUT 8
#define MSG_OK 9

struct EID {
    uint8_t eid_[SECURITY_PARAMETER_SIZE];

    EID() { memset(eid_, 0, sizeof(eid_)); }

    EID(const EID &eid) { memcpy(eid_, eid.eid_, SECURITY_PARAMETER_SIZE); }

    bool operator==(const EID &o) const {
        return memcmp(eid_, o.eid_, SECURITY_PARAMETER_SIZE) == 0;
    }

    uint8_t *to_bytes(uint8_t *buf) const {
        memcpy(buf, eid_, SECURITY_PARAMETER_SIZE);
        return buf + SECURITY_PARAMETER_SIZE;
    }

    static const uint8_t *from_bytes(const uint8_t *buf, EID *eid) {
        memcpy(eid->eid_, buf, SECURITY_PARAMETER_SIZE);
        return buf + SECURITY_PARAMETER_SIZE;
    }

    static constexpr size_t size() { return SECURITY_PARAMETER_SIZE; }
};

struct AckMessage {
// +----------+-----------+------+-------+
// | 1        | 4         | 16   | 4     |
// +----------+-----------+------+-------+
// | MSG_TYPE | CLIENT_ID | EID  | TRUST |
// +----------+-----------+------+-------+

    uint32_t client_id;
    EID eid_bc;
    Trust trust;

    uint8_t *to_bytes(uint8_t *msg_buf, size_t msg_buf_len) const {
        check(msg_buf_len >= this->size());

        uint8_t *cur = msg_buf;
        *cur = MSG_TYPE_ACK;
        ++cur;
        cur = ::to_bytes(cur, client_id);
        cur = eid_bc.to_bytes(cur);
        cur = trust.to_bytes(cur);;

        return cur;
    }

    static const uint8_t *from_bytes(const uint8_t *msg_buf, AckMessage *ack_msg) {
        check(msg_buf[0] == MSG_TYPE_ACK);
        const uint8_t *cur = msg_buf+1;
        cur = ::from_bytes(cur, &ack_msg->client_id);
        cur = EID::from_bytes(cur, &ack_msg->eid_bc);
        cur = Trust::from_bytes(cur, &ack_msg->trust);

        return cur;
    }
    
    static constexpr size_t size() { return 1 + sizeof(client_id) + EID::size() + Trust::size(); }
};

struct CommitMessage {
// +----------+----------+---------+----------+----------+
// | 16       | 16       | 16      | 4        | 4        |
// +----------+----------+---------+----------+----------+
// | EID_BC   | EID_1    | EID_2   | PK_LEN_1 | PK_LEN_2 |
// +----------+----------+---------+----------+----------+
// +----------+----------+---------+----------+----------+
// | PK_LEN_1 | PK_LEN_2 | 4       | ...      | 4        |
// +----------+----------+---------+----------+----------+
// | PK_1     | PK_2     | TRUST_1 | ...      | TRUST_N  |
// +----------+----------+---------+----------+----------+

    EID eid_bc;
    EID eid[N_TEE];

    std::vector<uint8_t> pk[N_TEE];

    std::vector<Trust> trust;

    explicit CommitMessage(size_t n_prot_mpc_client) {
        trust = std::vector<Trust>(n_prot_mpc_client);
    }

    static constexpr size_t fixed_size(size_t n_prot_mpc_client) {
        return EID::size() * (1 + N_TEE)
            + Trust::size() * n_prot_mpc_client
            + sizeof(uint32_t) * N_TEE;
    }

    uint8_t *to_bytes(uint8_t *msg_buf, size_t msg_buf_len) const {
        size_t required_len = fixed_size(trust.size());
        for (size_t i=0; i<N_TEE; ++i) {
            required_len += pk[i].size();
        }
        check(required_len <= msg_buf_len);

        uint8_t *cur = msg_buf;
        cur = eid_bc.to_bytes(cur);
        for (size_t i=0; i<N_TEE; ++i) {
            cur = eid[i].to_bytes(cur);
        }
        for (size_t i=0; i<N_TEE; ++i) {
            cur = ::to_bytes(cur, pk[i].size());
        }
        for (size_t i=0; i<N_TEE; ++i) {
            memcpy(cur, pk[i].data(), pk[i].size());
            cur += pk[i].size();
        }

        for (size_t i=0; i<trust.size(); ++i) {
            cur = trust[i].to_bytes(cur);
        }

        return cur;
    }

    static const uint8_t *from_bytes(
        const uint8_t *msg_buf,
        size_t msg_buf_len,
        size_t n_prot_mpc_client,
        CommitMessage *msg
    ) {
        msg->trust = std::vector<Trust>(n_prot_mpc_client);
        size_t required_len = fixed_size(n_prot_mpc_client);
        check(required_len <= msg_buf_len);
        const uint8_t *cur = msg_buf;
        cur = EID::from_bytes(cur, &msg->eid_bc);
        for (size_t i=0; i<N_TEE; ++i) {
            cur = EID::from_bytes(cur, &msg->eid[i]);
        }
        uint32_t pk_len[N_TEE];
        for (size_t i=0; i<N_TEE; ++i) {
            cur = ::from_bytes(cur, pk_len + i);
            required_len += pk_len[i];
        }
        
        check(required_len <= msg_buf_len);
        for (size_t i=0; i<N_TEE; ++i) {
            msg->pk[i] = std::vector<uint8_t>(cur, cur+pk_len[i]);
            cur += pk_len[i];
        }

        for (size_t i=0; i<n_prot_mpc_client; ++i) {
            cur = Trust::from_bytes(cur, &msg->trust[i]);
        }

        return cur;
    }
};

struct SignedMessage {
// +---------+---------+----------+----------+
// | 4       | 4       | MSG_LEN  | SIG_LEN  |
// +---------+---------+----------+----------+
// | MSG_LEN | SIG_LEN | MSG      | SIG      |
// +---------+---------+----------+----------+
    uint8_t *msg;
    uint32_t msg_len;

    uint8_t *sig;
    uint32_t sig_len;
};

struct EntityInfo {
    bool is_tee = false;
    size_t id = 0;

    EntityInfo() = default;
    EntityInfo(bool is_tee, size_t id) : is_tee(is_tee), id(id) {}
};

struct IDMap {
private:
    std::unordered_map<size_t, size_t> id_map_;      // prot_mpc_id --> sec_agg_id
    std::unordered_map<size_t, size_t> id_rev_map_;  // sec_agg_id --> prot_mpc_id

public:
    IDMap() = default;

    IDMap(const std::vector<Trust> &trust) {
        size_t nth = 0;
        for (size_t i=0; i<trust.size(); ++i) {
            if (trust[i] == Trust::NOT_TRUST()) {
                id_map_[i] = nth + N_TEE;
                id_rev_map_[nth + N_TEE] = i;
                ++nth;
            }
        }
    }

    EntityInfo to_entity_info(size_t id) {
        return id < N_TEE ? EntityInfo{true, id} : EntityInfo{false, id_rev_map_[id]};
    }

    EntityInfo to_entity_info(const GroupInfo &info) {
        return to_entity_info(
            GroupInfo::to_client_id(info)
        );
    }

    size_t to_sec_agg_id(const EntityInfo &info) {
        if (info.is_tee) {
            check(info.id < N_TEE);
            return info.id;
        }
        else {
            check(id_map_.find(info.id) != id_map_.end());
            return id_map_[info.id];
        }
        return -1;
    }
};

#define MY_ECALL_SUCCESS 0xbeaf
#define MY_ECALL_FAILURE 0xdeadbeaf

#define SGX_SERVER_LISTEN_SERVER_PORT 20005
#define SGX_SERVER_LISTEN_CLIENT_PORT 20006
#define AMD_SERVER_PORT 20007
#define CLIENT_PORT 30008

static inline void to_printable(
    const uint8_t *inp,
    size_t ilen,
    uint8_t *outp,
    size_t oupt_buf_len
) {
    check(oupt_buf_len >= ilen*2 + 1);

    static const char digits[] = "0123456789ABCDEF";
    for (size_t i=0; i<ilen; ++i) {
        outp[i*2] = digits[inp[i]>>4];
        outp[i*2 + 1] = digits[inp[i]&0xf];
    }
    outp[ilen * 2] = 0;
}

#define CONNECT_PERIOD 1000ms

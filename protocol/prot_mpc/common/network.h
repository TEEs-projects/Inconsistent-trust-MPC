#pragma once

#include <memory>
#include <asio.hpp>

#include "constant.h"

using namespace asio;

static inline void send_signed_msg(
    std::unique_ptr<ip::tcp::socket> &conn, 
    const SignedMessage &msg
) {
    uint8_t msg_len[4], sig_len[4];
    ::to_bytes(msg_len, msg.msg_len);
    ::to_bytes(sig_len, msg.sig_len);

    size_t n_write = 0;
    n_write += conn->write_some(buffer(msg_len, 4));
    n_write += conn->write_some(buffer(sig_len, 4));
    n_write += conn->write_some(buffer(msg.msg, msg.msg_len));
    n_write += conn->write_some(buffer(msg.sig, msg.sig_len));

#ifndef NDEBUG
    printf("msg_len: %u, sig_len: %u, n_read: %u\n", (unsigned)msg.msg_len, (unsigned)msg.sig_len, (unsigned)n_write);
    fflush(stdout);
#endif

    check(n_write == 4 + 4 + msg.msg_len + msg.sig_len);
}

// msg->msg and msg->sig should be pointed to the buffer
static inline SignedMessage recv_signed_msg(
    std::unique_ptr<ip::tcp::socket> &conn, 
    uint8_t *msg_buf,
    size_t msg_buf_len,
    uint8_t *sig_buf,
    size_t sig_buf_len
) {
    SignedMessage ret;
    ret.msg = msg_buf;
    ret.sig = sig_buf;

    uint8_t msg_len[4], sig_len[4];
    size_t n_read = 0;
    n_read += read(*conn, buffer(msg_len, 4));
    n_read += read(*conn, buffer(sig_len, 4));
    check(n_read == 4 + 4);

    ::from_bytes(msg_len, &ret.msg_len);
    ::from_bytes(sig_len, &ret.sig_len);
    check(ret.msg_len <= msg_buf_len && ret.sig_len <= sig_buf_len);

    n_read += read(*conn, buffer(ret.msg, ret.msg_len));
    n_read += read(*conn, buffer(ret.sig, ret.sig_len));

    check(n_read == 4 + 4 + ret.msg_len + ret.sig_len);

    return ret;
}

static inline size_t confirm_client_id(std::unique_ptr<ip::tcp::socket> &conn) {
    uint8_t buf[4];
    size_t n_read = read(*conn, buffer(buf, 4));
    check(n_read == 4);
    uint32_t id;
    from_bytes(buf, &id);
    return id;
}

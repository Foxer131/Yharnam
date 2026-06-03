#include "protocols/KdcClient.h"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace {

constexpr int kTimeoutSeconds = 10;
constexpr size_t kMaxResponse = 16u * 1024 * 1024;  // sanity cap (16 MiB)

bool sendAll(int fd, const uint8_t* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = send(fd, buf + sent, n - sent, 0);
        if (r <= 0) return false;
        sent += static_cast<size_t>(r);
    }
    return true;
}

bool recvAll(int fd, uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

int connectTo(const std::string& host, uint16_t port) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        struct timeval tv{};
        tv.tv_sec = kTimeoutSeconds;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

}  // namespace

namespace KdcClient {

std::optional<std::vector<uint8_t>> exchange(const std::string& host, uint16_t port,
                                             const uint8_t* request, size_t requestLen) {
    int fd = connectTo(host, port);
    if (fd < 0) {
        return std::nullopt;
    }

    const uint8_t prefix[4] = {
        static_cast<uint8_t>((requestLen >> 24) & 0xff),
        static_cast<uint8_t>((requestLen >> 16) & 0xff),
        static_cast<uint8_t>((requestLen >> 8) & 0xff),
        static_cast<uint8_t>(requestLen & 0xff),
    };

    std::optional<std::vector<uint8_t>> result;

    if (sendAll(fd, prefix, sizeof(prefix)) && sendAll(fd, request, requestLen)) {
        uint8_t lenBuf[4];
        if (recvAll(fd, lenBuf, sizeof(lenBuf))) {
            const size_t responseLen = (static_cast<size_t>(lenBuf[0]) << 24) |
                                       (static_cast<size_t>(lenBuf[1]) << 16) |
                                       (static_cast<size_t>(lenBuf[2]) << 8) |
                                       static_cast<size_t>(lenBuf[3]);
            if (responseLen > 0 && responseLen <= kMaxResponse) {
                std::vector<uint8_t> response(responseLen);
                if (recvAll(fd, response.data(), responseLen)) {
                    result = std::move(response);
                }
            }
        }
    }

    close(fd);
    return result;
}

}  // namespace KdcClient

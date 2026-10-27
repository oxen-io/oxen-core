#include "io_ledger_tcp.hpp"

#include <oxenc/endian.h>

#include <array>
#include <cstring>
#include <stdexcept>

#include "common/oxen.h"
#include "epee/misc_log_ex.h"
#include "log.hpp"
#include "logging/oxen_logger.h"

extern "C" {
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
}

namespace hw::io {

static auto logcat = log::Cat("device.io");

static std::string to_string(const addrinfo* a) {
    std::array<char, INET6_ADDRSTRLEN> buf;
    std::string addr;
#ifdef _WIN32
    unsigned long buflen = buf.size();
    if (auto rc = WSAAddressToString(a->ai_addr, a->ai_addrlen, nullptr, buf.data(), &buflen);
        rc == 0)
        addr = buf.data();
    else
        addr = "[error:"s + std::to_string(rc) + "]";
#else
    if (inet_ntop(a->ai_family, a->ai_addr, buf.data(), buf.size()))
        addr = buf.data();
    else
        addr = "[error:"s + strerror(errno) + "]";
#endif
    if (a->ai_family == AF_INET)
        (addr += ':') += std::to_string(reinterpret_cast<sockaddr_in*>(a->ai_addr)->sin_port);
    else if (a->ai_family == AF_INET6)
        (addr += ':') += std::to_string(reinterpret_cast<sockaddr_in6*>(a->ai_addr)->sin6_port);
    return addr;
}

void ledger_tcp::connect() {
    disconnect();

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        throw std::runtime_error{"Failed to open socket: "s + strerror(errno)};
    auto closer = oxen::defer([&] { close(fd); });

#ifdef _WIN32
    unsigned long blocking_param = 1;  // 1 = make non-blocking, 0 = blocking
    if (auto result = ioctlsocket(fd, FIONBIO, &blocking_param); result != NO_ERROR)
        throw std::runtime_error{"ioctlsocket failed with error: " + std::to_string(result)};
#else
    if (-1 == fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK))
        throw std::runtime_error{"Failed to set socket non-blocking: "s + strerror(errno)};
#endif

    addrinfo* addr;
    if (int rc = getaddrinfo(host.data(), port.data(), nullptr, &addr); rc != 0)
        throw std::runtime_error{
                "Failed to resolve " + host + ":" + port + ": " + gai_strerror(rc)};
    auto addr_free = oxen::defer([&] { freeaddrinfo(addr); });

    const addrinfo* a;
    bool connected = false;
    const char* err = "An unknown error occurred";
    for (a = addr; a && !connected; a = a->ai_next) {
        log::debug(logcat, "Attempting to connect to {}", to_string(a));
        int rc = ::connect(fd, a->ai_addr, a->ai_addrlen);
        connected = rc == 0;
        if (rc == -1) {
            if (errno == EINPROGRESS) {
                timeval timeo;
                timeo.tv_sec =
                        std::chrono::duration_cast<std::chrono::seconds>(connect_timeout).count();
                timeo.tv_usec = (connect_timeout % 1s).count();
                fd_set myset;
                FD_ZERO(&myset);
                FD_SET(fd, &myset);
                rc = select(fd + 1, nullptr, &myset, nullptr, &timeo);
                if (rc > 0)
                    connected = true;
                else if (rc == 0)
                    err = "Connection timed out";
                else
                    err = strerror(errno);
            } else {
                err = strerror(errno);
            }
        }
    }
    if (!connected)
        throw std::runtime_error{"Failed to connect to " + host + ":" + port + ": " + err};

    log::debug(logcat, "Connected to {}", to_string(a));

#ifdef _WIN32
    blocking_param = 0;
    if (auto result = ioctlsocket(fd, FIONBIO, &blocking_param); result != NO_ERROR)
        throw std::runtime_error{"ioctlsocket failed with error: " + std::to_string(result)};
#else
    if (-1 == fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK))
        throw std::runtime_error{"Failed to set socket back to blocking: "s + strerror(errno)};
#endif

    timeval timeo;
    timeo.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(exchange_timeout).count();
    timeo.tv_usec = (exchange_timeout % 1s).count();

    // The reinterpret_cast here is needed for Windows's shitty imitation of the api
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeo), sizeof(timeo));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeo), sizeof(timeo));

    sockfd = std::make_unique<int>(fd);
    closer.cancel();
}

void ledger_tcp::disconnect() {
    if (!sockfd)
        return;

    close(*sockfd);
    sockfd.reset();
}

ledger_tcp::~ledger_tcp() {
    disconnect();
}

bool ledger_tcp::connected() const {
    return (bool)sockfd;
}

void full_read(int fd, unsigned char* to, int size) {
    while (size > 0) {
        auto read_size = read(fd, to, size);
        if (read_size == -1)
            throw std::runtime_error{
                    "Failed to read from hardware wallet socket: "s + strerror(errno)};
        size -= read_size;
        to += read_size;
    }
}

void full_write(int fd, const unsigned char* from, int size) {
    while (size > 0) {
        auto wrote = write(fd, from, size);
        if (wrote == -1)
            throw std::runtime_error{
                    "Failed to write to hardware wallet socket: "s + strerror(errno)};
        size -= wrote;
        from += wrote;
    }
}

int ledger_tcp::exchange(
        const unsigned char* command,
        unsigned int cmd_len,
        unsigned char* response,
        unsigned int max_resp_len,
        bool user_input) {
    if (!sockfd)
        throw std::runtime_error{"Unable to exchange data with hardware wallet: not connected"};

    // Sending: [SIZE][DATA], where SIZE is a uint32_t in network order
    uint32_t size = oxenc::host_to_big(cmd_len);
    const unsigned char* size_bytes = reinterpret_cast<const unsigned char*>(&size);
    full_write(*sockfd, size_bytes, 4);
    full_write(*sockfd, command, cmd_len);

    // Receiving: [SIZE][DATA], where SIZE is the length of DATA minus 2 (WTF) because the last two
    // bytes of DATA are a 2-byte, u16 status code and... therefore not... included.  Good job,
    // Ledger devs.
    full_read(*sockfd, reinterpret_cast<unsigned char*>(&size), 4);
    auto data_size = oxenc::big_to_host(size) + 2;

    if (data_size > max_resp_len)
        throw std::runtime_error{
                "Hardware wallet returned unexpectedly large response: got " +
                std::to_string(data_size) + " bytes, expected <= " + std::to_string(max_resp_len)};

    full_read(*sockfd, response, data_size);

    return data_size;
}

}  // namespace hw::io

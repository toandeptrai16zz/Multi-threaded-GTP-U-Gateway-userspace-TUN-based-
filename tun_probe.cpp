#include "gtpu_encap.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

constexpr size_t GTPU_HEADER_SIZE = 8;
constexpr size_t MAX_IPV4_PACKET_SIZE = 65535;
constexpr size_t MAX_UDP_PAYLOAD_SIZE = 65507;
constexpr uint32_t TEID = 1;
constexpr uint16_t GTPU_UDP_PORT = 2152;

bool write_all(int fd, const unsigned char *data, size_t len)
{
    size_t written = 0;
    while (written < len) {
        const ssize_t result = write(fd, data + written, len - written);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "Error writing packet to tun0: " << strerror(errno) << std::endl;
            return false;
        }
        if (result == 0) {
            std::cerr << "Writing packet to tun0 made no progress" << std::endl;
            return false;
        }
        written += static_cast<size_t>(result);
    }
    return true;
}

} // namespace

int main()
{
    const int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        std::cerr << "Could not create UDP socket: " << strerror(errno) << std::endl;
        return 1;
    }

    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(GTPU_UDP_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(udp_fd, reinterpret_cast<sockaddr *>(&local_addr), sizeof(local_addr)) < 0) {
        std::cerr << "Could not bind UDP socket to 127.0.0.1:2152: "
                  << strerror(errno) << std::endl;
        close(udp_fd);
        return 1;
    }

    const int tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        std::cerr << "Could not open /dev/net/tun: " << strerror(errno) << std::endl;
        close(udp_fd);
        return 1;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, "tun0", IFNAMSIZ - 1);
    if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
        std::cerr << "ioctl TUNSETIFF failed: " << strerror(errno) << std::endl;
        close(tun_fd);
        close(udp_fd);
        return 1;
    }
    std::cout << "TUN interface " << ifr.ifr_name << " initialized successfully."
              << std::endl;

    unsigned char ip_buffer[MAX_IPV4_PACKET_SIZE];
    unsigned char gtpu_buffer[MAX_IPV4_PACKET_SIZE + GTPU_HEADER_SIZE];
    unsigned char received_buffer[MAX_UDP_PAYLOAD_SIZE];

    while (true) {
        const ssize_t read_len = read(tun_fd, ip_buffer, sizeof(ip_buffer));
        if (read_len < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "Error reading packet from tun0: " << strerror(errno) << std::endl;
            break;
        }
        if (read_len < static_cast<ssize_t>(sizeof(struct iphdr))) {
            std::cerr << "Packet too short for an IPv4 header." << std::endl;
            continue;
        }

        const auto *ip = reinterpret_cast<const struct iphdr *>(ip_buffer);
        if (ip->version != 4) {
            std::cerr << "Ignoring non-IPv4 packet." << std::endl;
            continue;
        }

        const size_t ip_len = static_cast<size_t>(read_len);
        const size_t gtpu_len = gtpu_encap(
            ip_buffer, ip_len, TEID, gtpu_buffer, sizeof(gtpu_buffer));
        if (gtpu_len == 0) {
            std::cerr << "Could not encapsulate IPv4 packet." << std::endl;
            continue;
        }
        if (gtpu_len > sizeof(received_buffer)) {
            std::cerr << "Encapsulated packet exceeds the maximum UDP payload size."
                      << std::endl;
            continue;
        }

        const ssize_t sent_len = sendto(
            udp_fd, gtpu_buffer, gtpu_len, 0,
            reinterpret_cast<const sockaddr *>(&local_addr), sizeof(local_addr));
        if (sent_len < 0) {
            std::cerr << "Error sending GTP-U packet: " << strerror(errno) << std::endl;
            continue;
        }
        if (static_cast<size_t>(sent_len) != gtpu_len) {
            std::cerr << "UDP send returned an incomplete datagram." << std::endl;
            continue;
        }

        const ssize_t received_len = recvfrom(
            udp_fd, received_buffer, sizeof(received_buffer), 0, nullptr, nullptr);
        if (received_len < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "Error receiving GTP-U packet: " << strerror(errno) << std::endl;
            break;
        }

        uint32_t received_teid = 0;
        size_t decapsulated_len = 0;
        const unsigned char *ip_packet = gtpu_decap(
            received_buffer, static_cast<size_t>(received_len),
            &received_teid, &decapsulated_len);
        if (ip_packet == nullptr) {
            continue;
        }
        if (received_teid != TEID) {
            std::cerr << "Ignoring packet with unexpected TEID " << received_teid << std::endl;
            continue;
        }
        write_all(tun_fd, ip_packet, decapsulated_len);
    }

    close(tun_fd);
    close(udp_fd);
    return 1;
}

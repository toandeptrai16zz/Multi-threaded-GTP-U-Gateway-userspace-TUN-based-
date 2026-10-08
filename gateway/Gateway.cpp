// gateway.cpp - Giai doan 2: GTP-U gateway mot thread, dung poll().
//
//   tun0 --read--> loc IPv4 --> gtpu_encap --> sendto 127.0.0.1:2152
//   udp 2152 --recvfrom--> gtpu_decap --> kiem tra IPv4 --> write --> tun0
//
// Chay:   sudo ./gateway [-i tun0] [-t teid] [-p port] [-v]
// Roi o terminal khac:
//   sudo ip addr add 10.9.0.1/24 dev tun0 && sudo ip link set tun0 up
//   ping -c3 10.9.0.2
//   sudo tcpdump -i lo -n udp port 2152 -vv

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../gtpu_encap.h"

namespace {

std::atomic<bool> g_running(true);
void on_signal(int) { g_running.store(false); }

struct Counters {
    uint64_t tun_read = 0, tun_short = 0, tun_not_ipv4 = 0;
    uint64_t encap_ok = 0, encap_fail = 0, send_fail = 0;
    uint64_t udp_read = 0, decap_ok = 0, decap_fail = 0, not_ipv4_inner = 0;
    uint64_t teid_mismatch = 0, tun_write_fail = 0;
};

struct Config {
    std::string ifname = "tun0";
    std::string bind_ip = "0.0.0.0";
    std::string peer_ip = "10.200.0.2";

    uint32_t teid = 9999;
    uint16_t port = 2152;
    bool verbose = false;
};

const char *proto_name(uint8_t p) {
    switch (p) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "other";
    }
}

void print_packet(const char *tag, const unsigned char *pkt, size_t len) {
    const struct iphdr *ip = reinterpret_cast<const struct iphdr *>(pkt);
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));
    std::printf("[%s] %s -> %s %s len=%zu ihl=%u\n", tag, src, dst,
                proto_name(ip->protocol), len, ip->ihl);
}

int tun_open(const std::string &name) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) { std::perror("open /dev/net/tun"); return -1; }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        std::perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    return fd;
}

int udp_open(const std::string &bind_ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        std::perror("socket");
        return -1;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1) {
        std::fprintf(stderr, "invalid bind IP: %s\n", bind_ip.c_str());
        close(fd);
        return -1;
    }

    if (bind(fd,
             reinterpret_cast<struct sockaddr *>(&addr),
             sizeof(addr)) < 0) {
        std::perror("bind");
        close(fd);
        return -1;
    }

    return fd;
}

void handle_tun(int tun_fd, int udp_fd, const Config &cfg, Counters &c,
                std::vector<unsigned char> &rx, std::vector<unsigned char> &tx,
                const struct sockaddr_in &peer) {
    ssize_t n = read(tun_fd, rx.data(), rx.size());
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN) std::perror("read tun");
        return;
    }
    ++c.tun_read;

    if (n < static_cast<ssize_t>(sizeof(struct iphdr))) { ++c.tun_short; return; }
    const struct iphdr *ip = reinterpret_cast<const struct iphdr *>(rx.data());
    if (ip->version != 4) { ++c.tun_not_ipv4; return; }   // bo IPv6, multicast ND...
    if (cfg.verbose) print_packet("tun->gtp", rx.data(), static_cast<size_t>(n));

    size_t m = gtpu_encap(rx.data(), static_cast<size_t>(n), cfg.teid, tx.data(), tx.size());
    if (m == 0) { ++c.encap_fail; return; }
    ++c.encap_ok;

    if (sendto(udp_fd, tx.data(), m, 0,
               reinterpret_cast<const struct sockaddr *>(&peer), sizeof(peer)) < 0) {
        ++c.send_fail;
    }
}

void handle_udp(int tun_fd, int udp_fd, const Config &cfg, Counters &c,
                std::vector<unsigned char> &rx) {
    ssize_t n = recvfrom(udp_fd, rx.data(), rx.size(), 0, nullptr, nullptr);
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN) std::perror("recvfrom");
        return;
    }
    ++c.udp_read;

    uint32_t teid = 0;
    size_t ip_len = 0;
    const unsigned char *inner = gtpu_decap(rx.data(), static_cast<size_t>(n), &teid, &ip_len);
    if (inner == nullptr) { ++c.decap_fail; return; }
    if (teid != cfg.teid) { ++c.teid_mismatch; return; }
    if ((inner[0] >> 4) != 4) { ++c.not_ipv4_inner; return; }
    ++c.decap_ok;
    if (cfg.verbose) print_packet("gtp->tun", inner, ip_len);

    if (write(tun_fd, inner, ip_len) < 0) ++c.tun_write_fail;
}

void print_stats(const Counters &c) {
    std::printf("[stats] tun_rx=%llu (short=%llu non_ipv4=%llu) encap=%llu/fail=%llu send_fail=%llu | "
                "udp_rx=%llu decap=%llu/fail=%llu teid_bad=%llu inner_not_v4=%llu tun_write_fail=%llu\n",
                (unsigned long long)c.tun_read, (unsigned long long)c.tun_short,
                (unsigned long long)c.tun_not_ipv4, (unsigned long long)c.encap_ok,
                (unsigned long long)c.encap_fail, (unsigned long long)c.send_fail,
                (unsigned long long)c.udp_read, (unsigned long long)c.decap_ok,
                (unsigned long long)c.decap_fail, (unsigned long long)c.teid_mismatch,
                (unsigned long long)c.not_ipv4_inner, (unsigned long long)c.tun_write_fail);
    std::fflush(stdout);
}

bool parse_args(int argc, char **argv, Config &cfg) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-i" && i + 1 < argc) cfg.ifname = argv[++i];
        else if (a == "-t" && i + 1 < argc) cfg.teid = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
        else if (a == "-p" && i + 1 < argc) cfg.port = static_cast<uint16_t>(std::strtoul(argv[++i], nullptr, 0));
        else if (a == "-v") cfg.verbose = true;
        else return false;
    }
    return true;
}

}  // namespace

int main(int argc, char **argv) {
    Config cfg;
    if (!parse_args(argc, argv, cfg)) {
        std::fprintf(stderr, "usage: %s [-i ifname] [-t teid] [-p port] [-v]\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;       // khong dat SA_RESTART: poll se tra ve EINTR de thoat
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    int tun_fd = tun_open(cfg.ifname);
    if (tun_fd < 0) return EXIT_FAILURE;
    int udp_fd = udp_open(cfg.port);
    if (udp_fd < 0) { close(tun_fd); return EXIT_FAILURE; }

    struct sockaddr_in peer;
    std::memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(cfg.port);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    std::printf("gateway: %s <-> udp/127.0.0.1:%u, TEID=%u (Ctrl+C de dung)\n",
                cfg.ifname.c_str(), cfg.port, cfg.teid);
    std::printf("tiep theo: sudo ip addr add 10.9.0.1/24 dev %s && sudo ip link set %s up\n",
                cfg.ifname.c_str(), cfg.ifname.c_str());

    std::vector<unsigned char> rx(65536 + GTPU_HEADER_SIZE);
    std::vector<unsigned char> tx(65536 + GTPU_HEADER_SIZE);
    Counters counters;
    struct pollfd fds[2] = {{tun_fd, POLLIN, 0}, {udp_fd, POLLIN, 0}};
    auto last_stats = std::chrono::steady_clock::now();

    while (g_running.load()) {
        int rc = poll(fds, 2, 1000);
        if (rc < 0) {
            if (errno == EINTR) continue;
            std::perror("poll");
            break;
        }
        if ((fds[0].revents | fds[1].revents) & POLLNVAL) break;

        if (fds[0].revents & POLLIN) handle_tun(tun_fd, udp_fd, cfg, counters, rx, tx, peer);
        if (fds[1].revents & POLLIN) handle_udp(tun_fd, udp_fd, cfg, counters, rx);

        auto now = std::chrono::steady_clock::now();
        if (now - last_stats >= std::chrono::seconds(2)) {
            print_stats(counters);
            last_stats = now;
        }
    }

    print_stats(counters);
    close(udp_fd);
    close(tun_fd);
    std::puts("gateway: da dung");
    return EXIT_SUCCESS;
}
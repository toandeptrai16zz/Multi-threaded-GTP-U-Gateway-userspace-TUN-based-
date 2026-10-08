// Test don vi cho gtpu_encap / gtpu_decap. Khong can root, khong can TUN.
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include "../gtpu_encap.h"

static std::vector<unsigned char> make_ip_packet(size_t n) {
    std::vector<unsigned char> p(n);
    for (size_t i = 0; i < n; ++i) p[i] = static_cast<unsigned char>(i * 7 + 1);
    p[0] = 0x45;  // IPv4, ihl=5
    return p;
}

static void test_roundtrip() {
    auto ip = make_ip_packet(84);
    unsigned char out[128];
    size_t n = gtpu_encap(ip.data(), ip.size(), 9999, out, sizeof(out));
    assert(n == 92);
    assert(out[0] == 0x30 && out[1] == 0xFF);
    assert(out[2] == 0x00 && out[3] == 84);                       // length big-endian
    assert(out[4] == 0 && out[5] == 0 && out[6] == 0x27 && out[7] == 0x0F);  // 9999

    uint32_t teid = 0; size_t len = 0;
    const unsigned char *inner = gtpu_decap(out, n, &teid, &len);
    assert(inner != nullptr);
    assert(teid == 9999 && len == 84);
    assert(std::memcmp(inner, ip.data(), 84) == 0);
}

static void test_truncated() {
    auto ip = make_ip_packet(84);
    unsigned char out[128];
    size_t n = gtpu_encap(ip.data(), ip.size(), 1, out, sizeof(out));
    uint32_t teid; size_t len;
    assert(gtpu_decap(out, 7, &teid, &len) == nullptr);       // ngan hon header
    assert(gtpu_decap(out, 8, &teid, &len) == nullptr);       // chi co header, rong
    assert(gtpu_decap(out, n - 1, &teid, &len) == nullptr);   // thieu 1 byte payload
    assert(gtpu_decap(out, n + 1, &teid, &len) == nullptr);   // du 1 byte
    assert(gtpu_decap(out, 0, &teid, &len) == nullptr);
}

static void test_bad_header() {
    auto ip = make_ip_packet(40);
    unsigned char out[64];
    size_t n = gtpu_encap(ip.data(), ip.size(), 1, out, sizeof(out));
    uint32_t teid; size_t len;

    unsigned char bad[64];
    std::memcpy(bad, out, n); bad[0] = 0x00;                  // flags sai
    assert(gtpu_decap(bad, n, &teid, &len) == nullptr);
    std::memcpy(bad, out, n); bad[0] = 0x32;                  // co sequence number: chua ho tro
    assert(gtpu_decap(bad, n, &teid, &len) == nullptr);
    std::memcpy(bad, out, n); bad[1] = 0x01;                  // khong phai G-PDU
    assert(gtpu_decap(bad, n, &teid, &len) == nullptr);
    std::memcpy(bad, out, n); bad[3] = 41;                    // length sai
    assert(gtpu_decap(bad, n, &teid, &len) == nullptr);
}

static void test_encap_limits() {
    auto ip = make_ip_packet(100);
    unsigned char out[200];
    assert(gtpu_encap(ip.data(), 100, 1, out, 107) == 0);     // out_cap thieu 1 byte
    assert(gtpu_encap(ip.data(), 100, 1, out, 108) == 108);   // vua du
    assert(gtpu_encap(ip.data(), 0, 1, out, sizeof(out)) == 0);
    assert(gtpu_encap(nullptr, 100, 1, out, sizeof(out)) == 0);
    assert(gtpu_encap(ip.data(), 100, 1, nullptr, sizeof(out)) == 0);

    std::vector<unsigned char> big(70000, 0x45), buf(70100);
    assert(gtpu_encap(big.data(), big.size(), 1, buf.data(), buf.size()) == 0);  // > 65535
    assert(gtpu_encap(big.data(), 65535, 1, buf.data(), buf.size()) == 65543);   // bien tren
}

static void test_null_args() {
    unsigned char pkt[16] = {0x30, 0xFF, 0, 8, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8};
    uint32_t teid; size_t len;
    assert(gtpu_decap(nullptr, 16, &teid, &len) == nullptr);
    assert(gtpu_decap(pkt, 16, nullptr, &len) == nullptr);
    assert(gtpu_decap(pkt, 16, &teid, nullptr) == nullptr);
    assert(gtpu_decap(pkt, 16, &teid, &len) != nullptr);      // goi nay hop le
}

int main() {
    test_roundtrip();
    test_truncated();
    test_bad_header();
    test_encap_limits();
    test_null_args();
    std::puts("tat ca test PASS");
    return 0;
}
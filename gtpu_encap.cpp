#include "gtpu_encap.h"

#include <arpa/inet.h>
#include <cstring>

size_t gtpu_encap(const unsigned char *ip_pkt, size_t ip_len,
                  uint32_t teid, unsigned char *out, size_t out_cap)
{
    if (out == nullptr || ip_pkt == nullptr || ip_len == 0 || ip_len > UINT16_MAX)
        return 0;
    if (out_cap < GTPU_HEADER_SIZE + ip_len)   // kiem tra TRUOC khi ghi
        return 0;

    out[0] = GTPU_FLAGS;
    out[1] = GTPU_MSG_GPDU;

    const uint16_t length = htons(static_cast<uint16_t>(ip_len));
    std::memcpy(out + 2, &length, sizeof(length));

    const uint32_t net_teid = htonl(teid);
    std::memcpy(out + 4, &net_teid, sizeof(net_teid));

    std::memcpy(out + GTPU_HEADER_SIZE, ip_pkt, ip_len);
    return GTPU_HEADER_SIZE + ip_len;
}

const unsigned char *gtpu_decap(const unsigned char *pkt, size_t len,
                                uint32_t *teid, size_t *ip_len)
{
    // len <= 8 cung loai luon goi rong; dam bao len - 8 khong bi tran so.
    if (pkt == nullptr || teid == nullptr || ip_len == nullptr ||
        len <= GTPU_HEADER_SIZE)
        return nullptr;

    if (pkt[0] != GTPU_FLAGS || pkt[1] != GTPU_MSG_GPDU)
        return nullptr;

    uint16_t net_length;
    std::memcpy(&net_length, pkt + 2, sizeof(net_length));
    const size_t payload_len = ntohs(net_length);
    if (payload_len != len - GTPU_HEADER_SIZE)
        return nullptr;

    uint32_t net_teid;
    std::memcpy(&net_teid, pkt + 4, sizeof(net_teid));
    *teid   = ntohl(net_teid);
    *ip_len = payload_len;
    return pkt + GTPU_HEADER_SIZE;
}
#pragma once
#include <cstddef>
#include <cstdint>

constexpr uint8_t GTPU_FLAGS       = 0x30;  // version 1, PT=1, khong co optional field
constexpr uint8_t GTPU_MSG_GPDU    = 0xFF;  // G-PDU: mang goi IP cua nguoi dung
constexpr size_t  GTPU_HEADER_SIZE = 8;

// Ghi header GTP-U + goi IP vao out. Tra ve so byte ghi, hoac 0 neu loi
// (tham so sai, ip_len == 0, ip_len > 65535, out_cap qua nho).
size_t gtpu_encap(const unsigned char *ip_pkt, size_t ip_len,
                  uint32_t teid, unsigned char *out, size_t out_cap);

// Kiem tra header va tra ve con tro toi goi IP ben trong (nam trong pkt),
// ghi TEID va do dai vao *teid, *ip_len. Tra ve nullptr neu goi khong hop le.
// Chi ho tro header toi thieu 8 byte (flags 0x30, G-PDU).
const unsigned char *gtpu_decap(const unsigned char *pkt, size_t len,
                                uint32_t *teid, size_t *ip_len);
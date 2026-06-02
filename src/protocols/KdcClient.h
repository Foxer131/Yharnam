#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Minimal Kerberos-over-TCP transport. The KDC framing (RFC 4120 7.2.2) is a
// 4-byte big-endian length prefix followed by the message bytes. Kept separate
// from KerberosInteraction so the krb5 logic does no socket I/O of its own.
namespace KdcClient {

/// @brief Sends @p request to host:port and returns the raw reply bytes.
/// @return The response, or std::nullopt on any connection/I/O failure.
std::optional<std::vector<uint8_t>> exchange(const std::string& host,
                                             uint16_t port,
                                             const uint8_t* request,
                                             size_t requestLen);

}  // namespace KdcClient

#include "Encoding.h"

#include <array>
#include <cctype>

namespace {

constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

}  // namespace

namespace Encoding {

bool isPrintable(const char* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        if (!std::isprint(static_cast<unsigned char>(data[i]))) {
            return false;
        }
    }
    return true;
}

std::string base64Encode(const char* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 3 <= len) {
        const auto b0 = static_cast<unsigned char>(data[i]);
        const auto b1 = static_cast<unsigned char>(data[i + 1]);
        const auto b2 = static_cast<unsigned char>(data[i + 2]);

        out += kBase64Alphabet[b0 >> 2];
        out += kBase64Alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += kBase64Alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)];
        out += kBase64Alphabet[b2 & 0x3f];
        i += 3;
    }

    const std::size_t remaining = len - i;
    if (remaining == 1) {
        const auto b0 = static_cast<unsigned char>(data[i]);
        out += kBase64Alphabet[b0 >> 2];
        out += kBase64Alphabet[(b0 & 0x03) << 4];
        out += "==";
    } else if (remaining == 2) {
        const auto b0 = static_cast<unsigned char>(data[i]);
        const auto b1 = static_cast<unsigned char>(data[i + 1]);
        out += kBase64Alphabet[b0 >> 2];
        out += kBase64Alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += kBase64Alphabet[(b1 & 0x0f) << 2];
        out += '=';
    }

    return out;
}

std::vector<std::uint8_t> base64Decode(const std::string& input) {
    std::array<int, 256> decodingTable;
    decodingTable.fill(-1);
    for (int i = 0; i < 64; ++i) {
        decodingTable[static_cast<unsigned char>(kBase64Alphabet[i])] = i;
    }

    std::vector<std::uint8_t> decoded;
    int accumulator = 0;
    int bits = -8;

    for (const unsigned char c : input) {
        const int value = decodingTable[c];
        if (value == -1) {
            break;  // padding or invalid character ends the stream
        }

        accumulator = (accumulator << 6) | value;
        bits += 6;

        if (bits >= 0) {
            decoded.push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xff));
            bits -= 8;
        }
    }

    return decoded;
}

}  // namespace Encoding

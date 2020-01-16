#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#define ETH_ALEN 6

namespace pol4b {
class Mac {
public:
    Mac() {}
    Mac(uint8_t addr_in[ETH_ALEN]) { memcpy(addr, addr_in, sizeof(Mac)); }

    uint8_t addr[ETH_ALEN];

    std::string to_string() const {
        char str_mac[18];
        sprintf(str_mac, "%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        return std::string(str_mac);
    }

    Mac &operator=(const Mac &rhs) {
        memcpy(addr, rhs.addr, sizeof(Mac));
        return *this;
    }

    Mac &operator=(const uint8_t rhs[ETH_ALEN]) {
        memcpy(addr, rhs, sizeof(Mac));
        return *this;
    }

    bool operator<(const Mac &rhs) const {
        return memcmp(addr, rhs.addr, sizeof(Mac)) < 0;
    }
};
}

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <arpa/inet.h>

namespace pol4b {
class Ip {
public:
    static const int size = 4;

public:
    Ip();
    Ip(const Ip &ip);
    Ip(uint32_t addr_in);

    uint8_t addr[size];

    std::string to_string() const;

    Ip &operator=(const Ip &rhs);
    Ip &operator=(const uint8_t rhs[size]);
    bool operator<(const Ip &rhs) const;

    operator std::string() const;
};
}

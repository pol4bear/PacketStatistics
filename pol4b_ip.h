#pragma once

#include <cstdint>
#include <string>
#include <arpa/inet.h>

namespace pol4b {
using Ip=uint32_t;
using IpPair=uint64_t;

static std::string ip_to_string(uint32_t ip) {
    return std::string(inet_ntoa(*(in_addr*)&ip));
}

static uint32_t get_src_ip(IpPair ip_pair) {
    return ip_pair >> 32;
}

static uint32_t get_dst_ip(IpPair ip_pair) {
    return ip_pair;
}
}

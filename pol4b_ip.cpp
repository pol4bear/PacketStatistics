#include <pol4b_ip.h>

using namespace std;
using namespace pol4b;

pol4b::Ip::Ip() {}

pol4b::Ip::Ip(const Ip &ip)
{
    memcpy(addr, ip.addr, size);
}

Ip::Ip(uint32_t addr_in)
{
    memcpy(addr, &addr_in, size);
}

std::string Ip::to_string() const
{
    return std::to_string(addr[0]) + "." + \
            std::to_string(int(addr[1])) + "." + \
            std::to_string(int(addr[2])) + "." + \
            std::to_string(int(addr[3]));;
}

Ip &Ip::operator=(const Ip &rhs)
{
    memcpy(addr, rhs.addr, size);
    return *this;
}

Ip &Ip::operator=(const uint8_t rhs[])
{
    memcpy(addr, rhs, size);
    return *this;
}

bool Ip::operator<(const Ip &rhs) const
{
    return uint32_t(*this->addr) < uint32_t(*rhs.addr);
}

Ip::operator string() const
{
    return to_string();
}

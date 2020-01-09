#pragma once

#include <functional>
#include <map>
#include <pthread.h>
#include <arpa/inet.h>
#include <experimental/filesystem>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include "pol4b_ether.h"
#include "pol4b_ip.h"

namespace pol4b{
// Classes
class MacPair;
class PacketInfo;
class PacketStatistics;

// Types
using OnFinished=std::function<void()>;
using OnError=std::function<void(int)>;
using MacEndpoints=std::map<Mac, PacketInfo>;
using MacConversations=std::map<MacPair, PacketInfo>;
using IpEndpoints=std::map<Ip, PacketInfo>;
using IpConversations=std::map<IpPair, PacketInfo>;

class PacketStatistics
{
public:
    // Constructors
    PacketStatistics(OnFinished cb_on_finished_in = nullptr, OnError cb_on_error_in = nullptr);

    // Getter & Setter
    bool get_state() const;
    std::string get_path() const;
    std::string get_file_name() const;
    const MacEndpoints *get_mac_endpoints() const;
    const MacConversations *get_mac_conversations() const;
    const IpEndpoints *get_ip_endpoints() const;
    const IpConversations *get_ip_conversations() const;

    // Public Methods
    void do_statistics(std::string path_in);

    // Error Code
    enum ErrorCode {
        ERR_DUP_REQ = 0x0,
        ERR_FILE_NOTFOUND,
        ERR_PCAP_OPEN
    };

private:
    // Private Members
    bool is_running;
    std::string path;
    std::string file_name;
    pthread_t job;
    MacEndpoints mac_endpoints;
    MacConversations mac_conversations;
    IpEndpoints ip_endpoints;
    IpConversations ip_conversations;

    // Callbacks
    std::function<void()> cb_on_finished;
    std::function<void(int)> cb_on_error;
    void on_finished();
    void on_error(int error_code);

    // Thread Methods
    static void *analyze(void *obj);
};

class MacPair {
public:
    Mac src_mac;
    Mac dst_mac;

    MacPair() {}
    MacPair(uint8_t src_mac_in[6], uint8_t dst_mac_in[6]) : src_mac(src_mac_in), dst_mac(dst_mac_in) {}

    MacPair &operator=(const MacPair &rhs) {
        src_mac = rhs.src_mac;
        dst_mac = rhs.dst_mac;
        return *this;
    }

    bool operator<(const MacPair &rhs) const {
        return src_mac < rhs.src_mac || dst_mac < rhs.dst_mac;
    }
};

class PacketInfo {
public:
    PacketInfo() : tx_packets(0), tx_size(0), rx_packets(0), rx_size(0) {}

    int tx_packets;
    int tx_size;
    int rx_packets;
    int rx_size;
};
}

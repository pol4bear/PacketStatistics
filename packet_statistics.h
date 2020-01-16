#pragma once

#include <functional>
#include <map>
#include <pthread.h>
#include <arpa/inet.h>
#include <experimental/filesystem>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include "pol4b_mac.h"
#include "pol4b_ip.h"

namespace pol4b{
template<class T>
class AddrPair;
class PacketStatistics;

using MacPair = AddrPair<Mac>;
using IpPair = AddrPair<Ip>;

class PacketStatistics
{
public:
    class PacketInfo;

    using MacEndpoints = std::map<Mac, PacketInfo>;
    using MacConversations = std::map<MacPair, PacketInfo>;
    using IpEndpoints=std::map<Ip, PacketInfo>;
    using IpConversations=std::map<IpPair, PacketInfo>;

    // Types
    using OnFinished = std::function<void()>;
    using OnError = std::function<void(int)>;


public:
    // Constructors
    PacketStatistics(OnFinished cb_on_finished_in = nullptr, OnError cb_on_error_in = nullptr);

    // Getter & Setter
    bool get_state() const;
    std::string get_path() const;
    std::string get_file_name() const;
    MacEndpoints *get_mac_endpoints();
    MacConversations *get_mac_conversations();
    IpEndpoints *get_ip_endpoints();
    IpConversations *get_ip_conversations();

    // Public Methods
    void do_statistics(std::string path_in);

    // Error Code
    enum ErrorCode {
        ERR_DUP_REQ = 0x0,
        ERR_FILE_NOTFOUND,
        ERR_PCAP_OPEN
    };

public:
    class PacketInfo {
    public:
        PacketInfo() : tx_packets(0), tx_size(0), rx_packets(0), rx_size(0) {}

        int tx_packets;
        int tx_size;
        int rx_packets;
        int rx_size;
    };

//private:
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

template<class T>
class AddrPair {
public:
    T src_addr;
    T dst_addr;

    AddrPair();
    AddrPair(T &src_addr_in, T &dst_addr_in);

    AddrPair &operator=(const AddrPair &rhs);

    bool operator<(const AddrPair &rhs) const;
};
}

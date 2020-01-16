#include "packet_statistics.h"

using namespace std;
using namespace pol4b;

namespace fs = std::experimental::filesystem;

// Constructors
PacketStatistics::PacketStatistics(OnFinished cb_on_finished_in, OnError cb_on_error_in) : is_running(false),
    cb_on_finished(cb_on_finished_in), cb_on_error(cb_on_error_in)
{
}

// Getter & Setter
bool PacketStatistics::get_state() const
{
    return is_running;
}

string PacketStatistics::get_path() const
{
    return path;
}

string PacketStatistics::get_file_name() const
{
    return file_name;
}

PacketStatistics::MacEndpoints *PacketStatistics::get_mac_endpoints()
{
    return &mac_endpoints;
}

PacketStatistics::MacConversations *PacketStatistics::get_mac_conversations()
{
    return &mac_conversations;
}

PacketStatistics::IpEndpoints *PacketStatistics::get_ip_endpoints()
{
    return &ip_endpoints;
}

PacketStatistics::IpConversations *PacketStatistics::get_ip_conversations()
{
    return &ip_conversations;
}

// Callbacks
void PacketStatistics::on_finished()
{
    is_running = false;

    if (cb_on_finished != nullptr)
        cb_on_finished();
}

void PacketStatistics::on_error(int error_code)
{
    is_running = false;

    if (cb_on_error != nullptr)
        cb_on_error(error_code);
}

// Public Methods
void PacketStatistics::do_statistics(string path_in)
{
    if(is_running) {
        on_error(ERR_DUP_REQ);
        return;
    }
    else if (!fs::exists(path_in)) {
        on_error(ERR_FILE_NOTFOUND);
        return;
    }

    is_running = true;
    mac_endpoints.clear();
    mac_conversations.clear();
    ip_endpoints.clear();
    ip_conversations.clear();

    path = path_in;
    file_name = path.substr(path.find_last_of("/") + 1);

    pthread_create(&job, nullptr, analyze, this);
}

// Thread Methods
void *PacketStatistics::analyze(void *object)
{
    PacketStatistics *obj = (PacketStatistics*)object;

    // Open pcap file
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(obj->path.c_str(), err_buf);

    if (handle == nullptr) {
        obj->on_error(obj->ERR_PCAP_OPEN);
        goto fin;
    }

    // Read packets from pcap
    pcap_pkthdr *packet_header;
    const uint8_t *packet;
    while (pcap_next_ex(handle, &packet_header, &packet) == 1) {
        ethhdr *ether_header = (ethhdr*)packet;
        bool mac_is_reverse = false;
        Mac src_mac(ether_header->h_source), dst_mac(ether_header->h_dest);
        MacPair mac_pair;

        // Make smaller mac goes left hand side
        if (src_mac < dst_mac) {
            mac_pair = MacPair(src_mac, dst_mac);
        }
        else {
            mac_pair = MacPair(dst_mac, src_mac);
            mac_is_reverse = true;
        }


        obj->mac_conversations.insert(make_pair(mac_pair, PacketInfo()));
        obj->mac_endpoints.insert(make_pair(src_mac, PacketInfo()));
        obj->mac_endpoints.insert(make_pair(dst_mac, PacketInfo()));

        // Update packet info of src & dst MAC
        if (!mac_is_reverse) {
            obj->mac_conversations[mac_pair].tx_packets++;
            obj->mac_conversations[mac_pair].tx_size += packet_header->caplen;
        }
        else {
            obj->mac_conversations[mac_pair].rx_packets++;
            obj->mac_conversations[mac_pair].rx_size += packet_header->caplen;
        }

        obj->mac_endpoints[src_mac].tx_packets++;
        obj->mac_endpoints[src_mac].tx_size += packet_header->caplen;
        obj->mac_endpoints[dst_mac].rx_packets++;
        obj->mac_endpoints[dst_mac].rx_size += packet_header->caplen;

        // If protocol is IP do statistics for IP
        if (ntohs(ether_header->h_proto) == ETH_P_IP) {
            iphdr *ip_header = (iphdr*)&packet[ETH_HLEN];
            bool ip_is_reverse = false;
            Ip src_ip(ip_header->saddr), dst_ip(ip_header->daddr);
            IpPair ip_pair;

            if (src_ip < dst_ip) {
                ip_pair = IpPair(src_ip, dst_ip);
            }
            else {
                ip_pair = IpPair(dst_ip, src_ip);
                ip_is_reverse = true;
            }

            obj->ip_conversations.insert(make_pair(ip_pair, PacketInfo()));
            obj->ip_endpoints.insert(make_pair(src_ip, PacketInfo()));
            obj->ip_endpoints.insert(make_pair(dst_ip, PacketInfo()));

            // Update packet info of src & dst IP
            if (!ip_is_reverse) {
                obj->ip_conversations[ip_pair].tx_packets++;
                obj->ip_conversations[ip_pair].tx_size += packet_header->caplen;
            }
            else {
                obj->ip_conversations[ip_pair].rx_packets++;
                obj->ip_conversations[ip_pair].rx_size += packet_header->caplen;
            }

            obj->ip_endpoints[ip_header->saddr].tx_packets++;
            obj->ip_endpoints[ip_header->saddr].tx_size += packet_header->caplen;
            obj->ip_endpoints[ip_header->daddr].rx_packets++;
            obj->ip_endpoints[ip_header->daddr].rx_size += packet_header->caplen;
        }
    }

    // Tell requester that statistics is finished
    obj->on_finished();

fin:
    return nullptr;
}

template<class T>
AddrPair<T>::AddrPair() {}

template<class T>
AddrPair<T>::AddrPair(T &src_addr_in, T &dst_addr_in)
    : src_addr(src_addr_in), dst_addr(dst_addr_in) {}

template<class T>
AddrPair<T> &AddrPair<T>::operator=(const AddrPair<T> &rhs)
{
    src_addr = rhs.src_addr;
    dst_addr = rhs.dst_addr;
}

template<class T>
bool AddrPair<T>::operator<(const AddrPair &rhs) const
{
    return memcmp(this, &rhs, sizeof(AddrPair)) < 0;
}

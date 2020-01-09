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

const MacEndpoints *PacketStatistics::get_mac_endpoints() const
{
    return &mac_endpoints;
}

const MacConversations *PacketStatistics::get_mac_conversations() const
{
    return &mac_conversations;
}

const IpEndpoints *PacketStatistics::get_ip_endpoints() const
{
    return &ip_endpoints;
}

const IpConversations *PacketStatistics::get_ip_conversations() const
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
        bool mac_exists = false, mac_is_reverse = false;
        MacPair mac_pair(ether_header->h_source, ether_header->h_dest), rev_mac_pair(ether_header->h_dest, ether_header->h_source);

        // Check if src & dst MAC pair is already in conversations
        if (obj->mac_conversations.find(mac_pair) != obj->mac_conversations.end()) {
            mac_exists = true;
        }
        else if (obj->mac_conversations.find(rev_mac_pair) != obj->mac_conversations.end()) {
            mac_exists = true;
            mac_is_reverse = true;
        }

        // If src & dst MAC pair doesn't exist insert to conversations
        if (!mac_exists) {
            obj->mac_conversations.insert(make_pair(mac_pair, PacketInfo()));
            obj->mac_endpoints.insert(make_pair(mac_pair.src_mac, PacketInfo()));
            obj->mac_endpoints.insert(make_pair(mac_pair.dst_mac, PacketInfo()));
            mac_exists = true;
        }

        // Update packet info of src & dst MAC
        if (!mac_is_reverse) {
            obj->mac_conversations[mac_pair].tx_packets++;
            obj->mac_conversations[mac_pair].tx_size += packet_header->caplen;
            obj->mac_endpoints[mac_pair.src_mac].tx_packets++;
            obj->mac_endpoints[mac_pair.src_mac].tx_size += packet_header->caplen;
            obj->mac_endpoints[mac_pair.dst_mac].rx_packets++;
            obj->mac_endpoints[mac_pair.dst_mac].rx_size += packet_header->caplen;
        }
        else {
            obj->mac_conversations[rev_mac_pair].rx_packets++;
            obj->mac_conversations[rev_mac_pair].rx_size += packet_header->caplen;
            obj->mac_endpoints[rev_mac_pair.src_mac].rx_packets++;
            obj->mac_endpoints[rev_mac_pair.src_mac].rx_size += packet_header->caplen;
            obj->mac_endpoints[rev_mac_pair.dst_mac].tx_packets++;
            obj->mac_endpoints[rev_mac_pair.dst_mac].tx_size += packet_header->caplen;
        }

        // If protocol is IP do statistics for IP
        if (ntohs(ether_header->h_proto) == ETH_P_IP) {
            iphdr *ip_header = (iphdr*)&packet[ETH_HLEN];
            bool ip_exists = false, ip_is_reverse = false;
            IpPair ip_pair = (uint64_t)ip_header->saddr << 32 | ip_header->daddr;
            IpPair rev_ip_pair = (uint64_t)ip_header->daddr << 32 | ip_header->saddr;

            // Check if src & dst IP pair is already in conversations
            if (obj->ip_conversations.find(ip_pair) != obj->ip_conversations.end()) {
                ip_exists = true;
            }
            else if (obj->ip_conversations.find(rev_ip_pair) != obj->ip_conversations.end()) {
                ip_exists = true;
                ip_is_reverse = true;
            }

            // If src & dst IP pair doesn't exist insert to conversations
            if (!ip_exists) {
                obj->ip_conversations.insert(make_pair(ip_pair, PacketInfo()));
                obj->ip_endpoints.insert(make_pair(ip_header->saddr, PacketInfo()));
                obj->ip_endpoints.insert(make_pair(ip_header->daddr, PacketInfo()));
                ip_exists = true;
            }

            // Update packet info of src & dst IP
            if (!ip_is_reverse) {
                obj->ip_conversations[ip_pair].tx_packets++;
                obj->ip_conversations[ip_pair].tx_size += packet_header->caplen;
            }
            else {
                obj->ip_conversations[rev_ip_pair].rx_packets++;
                obj->ip_conversations[rev_ip_pair].rx_size += packet_header->caplen;
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

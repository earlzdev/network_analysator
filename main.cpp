#include <pcap.h>
#include <iostream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    
    std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
    std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        std::cout << "Protocol: TCP" << std::endl;
        std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        std::cout << "Protocol: UDP" << std::endl;
        std::cout << "Source Port: " << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(udp_header->uh_dport) << std::endl;
    }

    std::cout << "Packet Length: " << pkthdr->len << " bytes" << std::endl;
    std::cout << "-------------------------" << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net;

    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        std::cerr << "Couldn't find default device: " << errbuf << std::endl;
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    std::cout << "Capturing on " << dev << std::endl;
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
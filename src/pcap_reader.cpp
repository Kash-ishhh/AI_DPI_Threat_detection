#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle =
        pcap_open_offline("../capture/live_test.pcap", errbuf);

    if (handle == nullptr) {
        std::cerr << "Failed to open PCAP: "
                  << errbuf << std::endl;
        return 1;
    }

    std::cout << "PCAP opened successfully!\n";

    int packet_count = 0;

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int result =
            pcap_next_ex(handle, &header, &packet);

        if (result == 1) {
    packet_count++;

    // Ethernet header is 14 bytes
    if (header->caplen >= 14) {

        // EtherType is stored at bytes 12-13
        uint16_t ether_type =
            (static_cast<uint16_t>(packet[12]) << 8) |
             static_cast<uint16_t>(packet[13]);

        std::cout
            << "\nPacket "
            << packet_count
            << " | Length: "
            << header->len
            << " bytes\n";

        std::cout
            << "  EtherType: 0x"
            << std::hex
            << ether_type
            << std::dec;

        if (ether_type == 0x0800) {
            std::cout << " (IPv4)";
        }
        else if (ether_type == 0x86DD) {
            std::cout << " (IPv6)";
        }
        else if (ether_type == 0x0806) {
            std::cout << " (ARP)";
        }
        else {
            std::cout << " (Other)";
        }

        std::cout << '\n';
    }
    else {
        std::cout
            << "\nPacket "
            << packet_count
            << " | Too short for Ethernet header\n";
    }
}
        else if (result == -2) {
            break;
        }
        else if (result == -1) {
            std::cerr
                << "Error reading PCAP: "
                << pcap_geterr(handle)
                << std::endl;
            break;
        }
    }

    pcap_close(handle);

    std::cout << "\nTotal packets read: "
              << packet_count
              << std::endl;

    return 0;
}
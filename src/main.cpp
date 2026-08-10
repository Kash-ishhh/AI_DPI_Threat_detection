#include <iostream>
#include <pcap.h>

int main() {
    const char* device =
        "\\Device\\NPF_{4DBB88ED-1143-4397-AC0B-77EDC391F812}";

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        device,
        65536,
        1,
        1000,
        errbuf
    );

    if (handle == nullptr) {
        std::cerr << "Failed to open interface:\n"
                  << errbuf << std::endl;
        return 1;
    }

    pcap_dumper_t* dumper =
        pcap_dump_open(handle, "../capture/live_test.pcap");

    if (dumper == nullptr) {
        std::cerr << "Failed to create PCAP file:\n"
                  << pcap_geterr(handle) << std::endl;

        pcap_close(handle);
        return 1;
    }

    std::cout << "Live capture started...\n";
    std::cout << "Capturing 10 packets...\n\n";

    int captured = 0;

    while (captured < 10) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int result =
            pcap_next_ex(handle, &header, &packet);

        if (result == 1) {
            pcap_dump(
                reinterpret_cast<u_char*>(dumper),
                header,
                packet
            );

            captured++;

            std::cout
                << "Packet "
                << captured
                << " captured - "
                << header->len
                << " bytes\n";
        }
        else if (result == -1) {
            std::cerr
                << "Capture error: "
                << pcap_geterr(handle)
                << std::endl;
            break;
        }
        else if (result == -2) {
            break;
        }
    }

    pcap_dump_close(dumper);
    pcap_close(handle);

    std::cout << "\nCapture finished.\n";
    std::cout << "Packets saved: "
              << captured
              << std::endl;

    return 0;
}
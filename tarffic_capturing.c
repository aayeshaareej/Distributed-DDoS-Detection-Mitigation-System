#include <mpi.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

//take length and packet bytes and geenrate hash using rolling polynomial hash and keeps the hash between 0–99999
int hash_func(const unsigned char* data, int len) {
    int h = 0;
    for (int i = 0; i < len; i++) {
        h = (h * 31 + data[i]) % 100000;
    }
    return h;
}

int main(int argc, char** argv) {
    int rank, size;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", 65535, 1, 1, errbuff);

    if (!handle) {
        if (rank == 0) printf("Error opening interface: %s\n", errbuff);
        //"eth0" → sniff traffic from interface eth0; 65535 → capture full packet size; 1 → enable promiscuous mode (capture all packets, even not destined for your IP) ;1 → timeout: 1 millisecond; errbuff → store errors
        MPI_Finalize();
        return 1;
    }

    int my_count = 0;
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (1) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue; // timeout or error

        int h = hash_func(packet, header->len) % size;

        if (h == rank) {
            my_count++;
            //printf("[Rank %d] Got packet of %d bytes\n", rank, header->len);
        }
    }

    pcap_close(handle);
    MPI_Finalize();
    return 0;
}
//mpicc tarffic.c -o tarffic -lpcap
//scp tarffic kali@slave1:~ 
//sudo mpirun --allow-run-as-root -np 4 ./tarffic
//sudo tcpreplay --intf1=eth0 PCAP-01-12_0750-0818/*.pcap


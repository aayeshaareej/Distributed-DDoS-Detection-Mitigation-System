#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_IPS 50000
#define SAMPLE_RATE 500
#define TRAFFIC_TIMEOUT 5  // Increased timeout to 5 seconds

typedef struct {
    char ip[16];
    unsigned long count;
    time_t first_seen;
    time_t last_seen;
    unsigned long total_bytes;
    unsigned short port;
    unsigned char protocol;
} ip_stats_t;

typedef struct {
    unsigned long total_packets;
    unsigned long total_bytes;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long syn_count;
    unsigned long small_packet_count;
    unsigned long malformed_packets;
    time_t start_time;
    time_t end_time;
    time_t last_packet_time;
    ip_stats_t *ip_stats;
    int ip_count;
    int attack_detected;
    double max_confidence;
    char attack_type[32];
    pcap_t *pcap_handle;
    pthread_t timeout_thread;
} traffic_stats_t;

volatile sig_atomic_t running = 1;
traffic_stats_t global_stats;

void signal_handler(int sig) {
    running = 0;
    if (global_stats.pcap_handle) {
        pcap_breakloop(global_stats.pcap_handle);
    }
}

void* timeout_monitor(void* arg) {
    traffic_stats_t *stats = (traffic_stats_t*)arg;
    int consecutive_empty_checks = 0;
    
    while (running) {
        sleep(1);
        
        if (!running) break;
        
        time_t current_time = time(NULL);
        double time_since_last_packet = difftime(current_time, stats->last_packet_time);
        
        // If we have packets and no traffic for timeout period, stop
        if (stats->total_packets > 0 && time_since_last_packet >= TRAFFIC_TIMEOUT) {
            printf("\n🛑 No traffic detected for %.0f seconds. Stopping capture...\n", time_since_last_packet);
            running = 0;
            if (stats->pcap_handle) {
                pcap_breakloop(stats->pcap_handle);
            }
            break;
        }
        
        // If no packets at all for extended period, stop
        if (stats->total_packets == 0) {
            consecutive_empty_checks++;
            if (consecutive_empty_checks >= 10) { // 10 seconds with zero packets
                printf("\n🛑 No packets captured for 10 seconds. Stopping...\n");
                printf("💡 Check: Is traffic being sent to eth0? Is the interface up?\n");
                running = 0;
                if (stats->pcap_handle) {
                    pcap_breakloop(stats->pcap_handle);
                }
                break;
            }
        } else {
            consecutive_empty_checks = 0;
        }
    }
    return NULL;
}

void init_stats(traffic_stats_t *stats) {
    stats->total_packets = 0;
    stats->total_bytes = 0;
    stats->tcp_packets = 0;
    stats->udp_packets = 0;
    stats->syn_count = 0;
    stats->small_packet_count = 0;
    stats->malformed_packets = 0;
    stats->start_time = time(NULL);
    stats->end_time = 0;
    stats->last_packet_time = time(NULL);
    stats->ip_count = 0;
    stats->attack_detected = 0;
    stats->max_confidence = 0.0;
    stats->pcap_handle = NULL;
    strcpy(stats->attack_type, "BENIGN");
    
    stats->ip_stats = malloc(MAX_IPS * sizeof(ip_stats_t));
    if (!stats->ip_stats) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
}

void free_stats(traffic_stats_t *stats) {
    if (stats->ip_stats) {
        free(stats->ip_stats);
    }
}

int find_ip_index(traffic_stats_t *stats, const char *ip, unsigned short port, unsigned char protocol) {
    for (int i = 0; i < stats->ip_count; i++) {
        if (strcmp(stats->ip_stats[i].ip, ip) == 0 && 
            stats->ip_stats[i].port == port && 
            stats->ip_stats[i].protocol == protocol) {
            return i;
        }
    }
    return -1;
}

void update_ip_stats(traffic_stats_t *stats, const char *ip, unsigned short port, 
                    unsigned char protocol, unsigned long packet_size) {
    int index = find_ip_index(stats, ip, port, protocol);
    
    if (index == -1) {
        if (stats->ip_count < MAX_IPS) {
            index = stats->ip_count;
            strncpy(stats->ip_stats[index].ip, ip, 15);
            stats->ip_stats[index].ip[15] = '\0';
            stats->ip_stats[index].count = 1;
            stats->ip_stats[index].total_bytes = packet_size;
            stats->ip_stats[index].port = port;
            stats->ip_stats[index].protocol = protocol;
            stats->ip_stats[index].first_seen = time(NULL);
            stats->ip_stats[index].last_seen = time(NULL);
            stats->ip_count++;
        }
    } else {
        stats->ip_stats[index].count++;
        stats->ip_stats[index].total_bytes += packet_size;
        stats->ip_stats[index].last_seen = time(NULL);
    }
}

double calculate_entropy(traffic_stats_t *stats) {
    if (stats->total_packets == 0) return 0.0;
    
    double entropy = 0.0;
    for (int i = 0; i < stats->ip_count; i++) {
        double p = (double)stats->ip_stats[i].count / stats->total_packets;
        if (p > 0) {
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

const char* detect_attack_type(traffic_stats_t *stats, double packet_rate, double entropy) {
    double syn_ratio = stats->total_packets > 0 ? (double)stats->syn_count / stats->total_packets : 0;
    double udp_ratio = stats->total_packets > 0 ? (double)stats->udp_packets / stats->total_packets : 0;
    double small_packet_ratio = stats->total_packets > 0 ? (double)stats->small_packet_count / stats->total_packets : 0;
    
    // High packet rate with low entropy = single source flood
    if (packet_rate > 10000 && entropy < 1.0) {
        return "Single-Source Flood";
    } else if (packet_rate > 5000 && udp_ratio > 0.9) {
        return "UDP Flood";
    } else if (packet_rate > 10000 && entropy > 4.0) {
        return "Distributed DNS Flood";
    } else if (syn_ratio > 0.7 && packet_rate > 5000) {
        return "SYN Flood";
    } else if (entropy > 5.0 && packet_rate > 3000) {
        return "Distributed NTP Flood";
    } else if (packet_rate > 2000) {
        return "Suspicious Traffic";
    } else {
        return "BENIGN";
    }
}

double calculate_confidence(double packet_rate, double entropy, const char* attack_type) {
    if (strcmp(attack_type, "BENIGN") == 0) {
        return 0.0;
    }
    
    double confidence = 0.0;
    
    // Base confidence on packet rate
    if (packet_rate > 20000) confidence = 0.95;
    else if (packet_rate > 10000) confidence = 0.85;
    else if (packet_rate > 5000) confidence = 0.70;
    else if (packet_rate > 2000) confidence = 0.50;
    
    // Adjust for entropy patterns
    if (strcmp(attack_type, "Single-Source Flood") == 0 && entropy < 0.5) {
        confidence += 0.1;
    } else if (strcmp(attack_type, "Distributed DNS Flood") == 0 && entropy > 4.0) {
        confidence += 0.1;
    }
    
    return (confidence > 0.99) ? 0.99 : confidence;
}

void check_attack(traffic_stats_t *stats) {
    time_t current_time = time(NULL);
    double elapsed = difftime(current_time, stats->start_time);
    if (elapsed < 1) return;
    
    double packet_rate = stats->total_packets / elapsed;
    double entropy = calculate_entropy(stats);
    
    const char* attack_type = detect_attack_type(stats, packet_rate, entropy);
    double confidence = calculate_confidence(packet_rate, entropy, attack_type);
    
    if (confidence > stats->max_confidence) {
        stats->max_confidence = confidence;
        strncpy(stats->attack_type, attack_type, 31);
        stats->attack_type[31] = '\0';
        stats->attack_detected = (confidence > 0.6) ? 1 : 0;
    }
}

void print_final_report(traffic_stats_t *stats) {
    time_t current_time = time(NULL);
    double elapsed = difftime(current_time, stats->start_time);
    double packet_rate = (elapsed > 0) ? stats->total_packets / elapsed : 0;
    double byte_rate = (elapsed > 0) ? stats->total_bytes / elapsed : 0;
    double entropy = calculate_entropy(stats);
    
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                      FINAL DDoS DETECTION REPORT                  ║\n");
    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    
    if (stats->attack_detected) {
        printf("║ 🔴 STATUS: ATTACK DETECTED                                      ║\n");
        printf("║    Type: %-20s Confidence: %5.1f%%                    ║\n", 
               stats->attack_type, stats->max_confidence * 100);
    } else {
        printf("║ 🟢 STATUS: NORMAL TRAFFIC                                       ║\n");
        printf("║    Type: %-20s Confidence: %5.1f%%                    ║\n", 
               stats->attack_type, (1.0 - stats->max_confidence) * 100);
    }
    
    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    printf("║ 📊 TRAFFIC STATISTICS                                            ║\n");
    printf("║    Duration: %8.1f seconds   Total Packets: %10lu       ║\n", elapsed, stats->total_packets);
    printf("║    Packet Rate: %6.1f pps    Byte Rate: %10.1f Bps      ║\n", packet_rate, byte_rate);
    printf("║    Source IPs: %6d                    ║\n", stats->ip_count);
    printf("║    TCP: %4lu (%4.1f%%)      UDP: %4lu (%4.1f%%)                 ║\n",
           stats->tcp_packets, stats->total_packets > 0 ? (double)stats->tcp_packets/stats->total_packets*100 : 0,
           stats->udp_packets, stats->total_packets > 0 ? (double)stats->udp_packets/stats->total_packets*100 : 0);
    printf("║    Malformed: %4lu (%4.1f%%)  Small Pkts: %4lu (%4.1f%%)        ║\n",
           stats->malformed_packets, stats->total_packets > 0 ? (double)stats->malformed_packets/stats->total_packets*100 : 0,
           stats->small_packet_count, stats->total_packets > 0 ? (double)stats->small_packet_count/stats->total_packets*100 : 0);
    
    if (stats->attack_detected && stats->ip_count > 0) {
        printf("╠════════════════════════════════════════════════════════════════════╣\n");
        printf("║ 🔍 ATTACK ANALYSIS & SOURCE IPs                                 ║\n");
        
        // Sort IPs by packet count
        for (int i = 0; i < stats->ip_count; i++) {
            for (int j = i + 1; j < stats->ip_count; j++) {
                if (stats->ip_stats[j].count > stats->ip_stats[i].count) {
                    ip_stats_t temp = stats->ip_stats[i];
                    stats->ip_stats[i] = stats->ip_stats[j];
                    stats->ip_stats[j] = temp;
                }
            }
        }
        
       
        
        printf("║                                                                  ║\n");
        printf("║    Top Source IPs:                                              ║\n");
        
        // Print top IPs with more details
        int printed = 0;
        for (int i = 0; i < stats->ip_count && printed < 8; i++) {
            double ip_percentage = (double)stats->ip_stats[i].count / stats->total_packets * 100;
            double avg_pkt_size = stats->ip_stats[i].count > 0 ? 
                (double)stats->ip_stats[i].total_bytes / stats->ip_stats[i].count : 0;
            const char* proto = stats->ip_stats[i].protocol == 6 ? "TCP" : 
                               stats->ip_stats[i].protocol == 17 ? "UDP" : "OTHER";
            
            if (ip_percentage > 0.1) { // Only show IPs with > 0.1% of traffic
                printf("║    %-15s : %6lu pkts (%5.1f%%) %s P:%d             ║\n",
                       stats->ip_stats[i].ip, stats->ip_stats[i].count, 
                       ip_percentage, proto, stats->ip_stats[i].port);
                printed++;
            }
        }
        
        if (printed == 0) {
            printf("║    No significant source IPs identified                      ║\n");
        }
    }
    
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    
    // Additional insights
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    traffic_stats_t *stats = (traffic_stats_t *)user_data;
    
    if (!running) return;
    
    stats->total_packets++;
    stats->total_bytes += pkthdr->len;
    stats->last_packet_time = time(NULL);
    
    // Skip malformed packets that are too small
    if (pkthdr->len < sizeof(struct ethhdr)) {
        stats->malformed_packets++;
        return;
    }
    
    if (pkthdr->len < 100) {
        stats->small_packet_count++;
    }
    
    struct ethhdr *eth = (struct ethhdr *)packet;
    
    // Check for different Ethernet types
    unsigned short ether_type = ntohs(eth->h_proto);
    
    if (ether_type == ETH_P_IP) {  // IPv4
        // Check if packet is large enough for IP header
        if (pkthdr->len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            stats->malformed_packets++;
            return;
        }
        
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
        char src_ip[INET_ADDRSTRLEN];
        unsigned short src_port = 0;
        unsigned char protocol = ip->protocol;
        
        inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
        
        // Check if packet is large enough for transport layer
        unsigned int ip_header_len = ip->ihl * 4;
        if (pkthdr->len < sizeof(struct ethhdr) + ip_header_len) {
            stats->malformed_packets++;
            return;
        }
        
        // Extract source port for TCP/UDP
        if (ip->protocol == IPPROTO_TCP) {
            if (pkthdr->len >= sizeof(struct ethhdr) + ip_header_len + sizeof(struct tcphdr)) {
                stats->tcp_packets++;
                struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header_len);
                src_port = ntohs(tcp->source);
                if (tcp->syn && !tcp->ack) {
                    stats->syn_count++;
                }
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            if (pkthdr->len >= sizeof(struct ethhdr) + ip_header_len + sizeof(struct udphdr)) {
                stats->udp_packets++;
                struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header_len);
                src_port = ntohs(udp->source);
            }
        }
        
        update_ip_stats(stats, src_ip, src_port, protocol, pkthdr->len);
    } else if (ether_type == ETH_P_IPV6) {  // IPv6
        // Skip IPv6 for now, but count it
        stats->malformed_packets++; // Treat IPv6 as "other" for now
    } else {
        // Other Ethernet types (ARP, etc.)
        stats->malformed_packets++;
    }
    
    if (stats->total_packets % SAMPLE_RATE == 0) {
        check_attack(stats);
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("🚀 C DDoS Detector - Robust Version\n");
    printf("📡 Monitoring interface: eth0\n");
    printf("⏰ Will auto-stop when traffic stops for %d seconds\n", TRAFFIC_TIMEOUT);
    printf("🔧 Enhanced packet parsing with malformed packet handling\n");
    printf("------------------------------------------------------------\n");
    
    init_stats(&global_stats);
    
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "❌ Couldn't open device eth0: %s\n", errbuf);
        fprintf(stderr, "💡 Check: sudo ip link set eth0 up\n");
        free_stats(&global_stats);
        return 1;
    }
    
    global_stats.pcap_handle = handle;
    
    // Use a broader filter to catch more packet types
    struct bpf_program fp;
    char filter_exp[] = "(ip or ip6)";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "❌ Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        // Try with simpler filter
        char simple_filter[] = "ip";
        if (pcap_compile(handle, &fp, simple_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "❌ Couldn't parse simple filter either: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            free_stats(&global_stats);
            return 1;
        }
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "❌ Couldn't install filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        free_stats(&global_stats);
        return 1;
    }
    
    if (pthread_create(&global_stats.timeout_thread, NULL, timeout_monitor, &global_stats) != 0) {
        fprintf(stderr, "❌ Failed to create timeout thread\n");
        pcap_close(handle);
        free_stats(&global_stats);
        return 1;
    }
    
    printf("🎯 Starting robust capture...\n");
    printf("💡 Handling malformed packets and various protocols\n");
    
    ret = pcap_loop(handle, 0, packet_handler, (u_char *)&global_stats);
    
    pthread_join(global_stats.timeout_thread, NULL);
    
    pcap_close(handle);
    global_stats.pcap_handle = NULL;
    
    global_stats.end_time = time(NULL);
    
    printf("\n\n");
    print_final_report(&global_stats);
    
    free_stats(&global_stats);
    
    return 0;
}

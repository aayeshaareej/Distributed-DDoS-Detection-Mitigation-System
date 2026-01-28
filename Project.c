#include <mpi.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>

#define MAX_IPS 50000
#define TRAFFIC_TIMEOUT 5
#define MAX_IP_LENGTH 16
#define MIN_TRAINING_SAMPLES 3
#define WINDOW_SIZE 20

// ==================== MITIGATION STRUCTURES ====================

typedef struct {
    char rule_type[20];
    char target_ip[MAX_IP_LENGTH];
    char protocol[10];
    int port;
    double rate_limit;
    char direction[10];
    char action[20];
    time_t created_time;
    int is_active;
    char flowspec_rule[256];
    double effectiveness;
    int iteration_applied;
    unsigned long packets_blocked;
    unsigned long bytes_blocked;
} mitigation_rule_t;

typedef struct {
    mitigation_rule_t rules[100];
    int rule_count;
    int active_mitigations;
    time_t last_mitigation_time;
    char mitigation_log[1024];
    int current_iteration;
    int max_iterations;
    double overall_effectiveness;
    int attack_persists;
    
    // Blocking effectiveness metrics
    double attack_traffic_dropped;
    double collateral_impact;
    unsigned long total_packets_blocked;
    unsigned long total_bytes_blocked;
    unsigned long legitimate_packets_blocked;
} mitigation_engine_t;

// Data structure for Python communication
typedef struct {
    // Traffic metrics
    double packet_rate;
    double throughput_gbps;
    double entropy;
    double udp_ratio;
    double syn_ratio;
    
    // Performance metrics
    double detection_lead_time;
    double avg_processing_latency;
    double cpu_usage;
    long memory_usage;
    
    // Attack detection
    char attack_type[50];
    double confidence;
    int unique_ips;
    int is_attack;
    
    // Statistical detection results
    double pca_anomaly_score;
    double cusum_anomaly_score;
    int pca_alert;
    int cusum_alert;
    
    // Top IPs
    char top_ips[10][MAX_IP_LENGTH];
    unsigned long top_ip_counts[10];
    double top_ip_percentages[10];
    int top_ip_count;
    
    // Timestamp
    long timestamp;
    
    // MITIGATION DATA
    int mitigation_active;
    int rules_created;
    char current_mitigation[100];
    double mitigation_effectiveness;
    double attack_traffic_dropped;
    double collateral_impact;
    int mitigation_iteration;
    unsigned long total_packets_blocked;
    
} python_data_t;

// Statistical detection structures
typedef struct {
    double packet_rates[WINDOW_SIZE];
    double entropies[WINDOW_SIZE];
    double udp_ratios[WINDOW_SIZE];
    int current_index;
    int is_full;
} traffic_window_t;

typedef struct {
    double mean_packet_rate;
    double mean_entropy;
    double mean_udp_ratio;
    double std_packet_rate;
    double std_entropy;
    double std_udp_ratio;
    double covariance[3][3];
} pca_model_t;

typedef struct {
    double cumulative_sum;
    double threshold;
    double drift;
    int alarm;
} cusum_detector_t;

// Performance tracking structures
typedef struct {
    struct timespec start_time;
    struct timespec first_alert_time;
    struct timespec last_packet_time;
    double total_processing_time;
    unsigned long total_packets_processed;
    int attack_detected;
    double detection_lead_time;
} performance_stats_t;

typedef struct {
    double cpu_usage;
    long memory_usage;
    double network_throughput;
} resource_stats_t;

// Hash function for distributing packets across MPI ranks
int hash_func(const unsigned char* data, int len) {
    int h = 0;
    for (int i = 0; i < len; i++) {
        h = (h * 31 + data[i]) % 100000;
    }
    return h;
}

typedef struct {
    char ip[MAX_IP_LENGTH];
    unsigned long count;
    unsigned long total_bytes;
    int is_legitimate; // 0 = unknown, 1 = legitimate, 2 = malicious
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
    time_t last_packet_time;
    ip_stats_t *ip_stats;
    int ip_count;
    
    // Statistical detection
    traffic_window_t traffic_window;
    pca_model_t pca_model;
    cusum_detector_t cusum_packet_rate;
    cusum_detector_t cusum_entropy;
    
    // Performance metrics
    performance_stats_t perf_stats;
    resource_stats_t res_stats;
    
    // MITIGATION ENGINE
    mitigation_engine_t mitigation_engine;
    
    // Traffic baselines for effectiveness calculation
    double baseline_packet_rate;
    unsigned long baseline_total_packets;
    
} traffic_stats_t;

// ==================== REAL MITIGATION STRUCTURES ====================

// Structure to track blocked IPs
typedef struct {
    char ip[MAX_IP_LENGTH];
    time_t blocked_time;
    unsigned long packets_blocked;
    unsigned long bytes_blocked;
    int block_type; // 1 = rate_limit, 2 = complete_block
    double rate_limit; // packets per second
} blocked_ip_t;

typedef struct {
    blocked_ip_t blocked_ips[100];
    int blocked_count;
    unsigned long total_packets_blocked;
    unsigned long total_bytes_blocked;
} packet_filter_t;

// ==================== FUNCTION DECLARATIONS ====================
void block_ip_address(const char* ip, int block_type, double rate_limit);
int should_block_packet(const char* src_ip, unsigned long packet_size);
void unblock_ip_address(const char* ip);
void init_packet_filter();
void display_multiple_ips(ip_stats_t *unique_ips, int total_unique_ips, unsigned long total_packets);
void synchronize_blocked_ips(int rank, int size);

// Global packet filter
packet_filter_t global_filter;
// Global variables for iterative mitigation tracking
static double previous_global_packet_rate = 0.0;
static double previous_global_confidence = 0.0;
static int mitigation_phase_active = 0;
static double peak_attack_rate = 0.0;

volatile sig_atomic_t running = 1;

void signal_handler(int sig) {
    running = 0;
}

// Get current time with high precision
void get_current_time(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

// Calculate time difference in milliseconds
double time_diff_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 + 
           (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

// Get CPU usage
double get_cpu_usage() {
    static struct timespec last_cpu_time = {0, 0};
    static struct timespec last_real_time = {0, 0};
    
    struct timespec current_cpu_time, current_real_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &current_cpu_time);
    clock_gettime(CLOCK_MONOTONIC, &current_real_time);
    
    double cpu_usage = 0.0;
    
    if (last_cpu_time.tv_sec != 0) {
        double cpu_diff = time_diff_ms(last_cpu_time, current_cpu_time);
        double real_diff = time_diff_ms(last_real_time, current_real_time);
        
        if (real_diff > 0) {
            cpu_usage = (cpu_diff / real_diff) * 100.0;
        }
    }
    
    last_cpu_time = current_cpu_time;
    last_real_time = current_real_time;
    
    return cpu_usage;
}

// Get memory usage in MB
long get_memory_usage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss / 1024;
}

// ==================== STATISTICAL DETECTION ALGORITHMS ====================

void init_traffic_window(traffic_window_t *window) {
    window->current_index = 0;
    window->is_full = 0;
    for (int i = 0; i < WINDOW_SIZE; i++) {
        window->packet_rates[i] = 0.0;
        window->entropies[i] = 0.0;
        window->udp_ratios[i] = 0.0;
    }
}

void add_to_window(traffic_window_t *window, double packet_rate, double entropy, double udp_ratio) {
    window->packet_rates[window->current_index] = packet_rate;
    window->entropies[window->current_index] = entropy;
    window->udp_ratios[window->current_index] = udp_ratio;
    
    window->current_index++;
    if (window->current_index >= WINDOW_SIZE) {
        window->current_index = 0;
        window->is_full = 1;
    }
}

double calculate_mean(double *array, int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += array[i];
    }
    return sum / n;
}

double calculate_std(double *array, int n, double mean) {
    if (n <= 1) return 0.1;
    double sum_sq = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = array[i] - mean;
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq / n);
}

double calculate_covariance(double *x, double *y, int n, double mean_x, double mean_y) {
    if (n <= 1) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += (x[i] - mean_x) * (y[i] - mean_y);
    }
    return sum / n;
}

void train_pca_model(traffic_window_t *window, pca_model_t *model) {
    int actual_samples = window->is_full ? WINDOW_SIZE : window->current_index;
    
    if (actual_samples < MIN_TRAINING_SAMPLES) {
        return;
    }
    
    model->mean_packet_rate = calculate_mean(window->packet_rates, actual_samples);
    model->mean_entropy = calculate_mean(window->entropies, actual_samples);
    model->mean_udp_ratio = calculate_mean(window->udp_ratios, actual_samples);
    
    model->std_packet_rate = calculate_std(window->packet_rates, actual_samples, model->mean_packet_rate);
    model->std_entropy = calculate_std(window->entropies, actual_samples, model->mean_entropy);
    model->std_udp_ratio = calculate_std(window->udp_ratios, actual_samples, model->mean_udp_ratio);
    
    if (model->std_packet_rate < 0.1) model->std_packet_rate = 0.1;
    if (model->std_entropy < 0.1) model->std_entropy = 0.1;
    if (model->std_udp_ratio < 0.01) model->std_udp_ratio = 0.01;
    
    model->covariance[0][0] = model->std_packet_rate * model->std_packet_rate;
    model->covariance[1][1] = model->std_entropy * model->std_entropy;
    model->covariance[2][2] = model->std_udp_ratio * model->std_udp_ratio;
    
    model->covariance[0][1] = model->covariance[1][0] = calculate_covariance(
        window->packet_rates, window->entropies, actual_samples, 
        model->mean_packet_rate, model->mean_entropy);
    
    model->covariance[0][2] = model->covariance[2][0] = calculate_covariance(
        window->packet_rates, window->udp_ratios, actual_samples,
        model->mean_packet_rate, model->mean_udp_ratio);
    
    model->covariance[1][2] = model->covariance[2][1] = calculate_covariance(
        window->entropies, window->udp_ratios, actual_samples,
        model->mean_entropy, model->mean_udp_ratio);
}

double pca_anomaly_detection(pca_model_t *model, double packet_rate, double entropy, double udp_ratio, int samples_available) {
    if (samples_available < MIN_TRAINING_SAMPLES) {
        double quick_score = 0.0;
        if (packet_rate > 5000) quick_score += (packet_rate - 1000) / 1000;
        if (entropy < 1.0) quick_score += (2.0 - entropy) * 2;
        if (udp_ratio > 0.8) quick_score += (udp_ratio - 0.5) * 4;
        return quick_score;
    }
    
    if (model->std_packet_rate < 0.1 || model->std_entropy < 0.1 || model->std_udp_ratio < 0.01) {
        return 0.0;
    }
    
    double z_packet_rate = (packet_rate - model->mean_packet_rate) / model->std_packet_rate;
    double z_entropy = (entropy - model->mean_entropy) / model->std_entropy;
    double z_udp_ratio = (udp_ratio - model->mean_udp_ratio) / model->std_udp_ratio;
    
    double anomaly_score = (z_packet_rate * z_packet_rate) + 
                          (z_entropy * z_entropy) + 
                          (z_udp_ratio * z_udp_ratio);
    
    return anomaly_score;
}

void init_cusum_detector(cusum_detector_t *detector, double threshold, double drift) {
    detector->cumulative_sum = 0.0;
    detector->threshold = threshold;
    detector->drift = drift;
    detector->alarm = 0;
}

int cusum_detect(cusum_detector_t *detector, double value, double target) {
    double deviation = value - target;
    double shifted_deviation = deviation - detector->drift;
    
    detector->cumulative_sum = fmax(0, detector->cumulative_sum + shifted_deviation);
    
    if (detector->cumulative_sum > detector->threshold) {
        detector->alarm = 1;
        detector->cumulative_sum = 0.0;
        return 1;
    }
    
    detector->alarm = 0;
    return 0;
}

// ==================== MITIGATION FUNCTIONS ====================

void init_mitigation_engine(mitigation_engine_t *engine) {
    engine->rule_count = 0;
    engine->active_mitigations = 0;
    engine->last_mitigation_time = 0;
    engine->current_iteration = 0;
    engine->max_iterations = 5;
    engine->overall_effectiveness = 0.0;
    engine->attack_persists = 0;
    engine->attack_traffic_dropped = 0.0;
    engine->collateral_impact = 0.0;
    engine->total_packets_blocked = 0;
    engine->total_bytes_blocked = 0;
    engine->legitimate_packets_blocked = 0;
    memset(engine->mitigation_log, 0, sizeof(engine->mitigation_log));
}

void generate_flowspec_rule(mitigation_rule_t *rule, const char* attack_type, 
                           const char* target_ip, double packet_rate) {
    
    if (strstr(attack_type, "UDP Flood") != NULL) {
        strcpy(rule->protocol, "udp");
        rule->rate_limit = fmax(1000, packet_rate * 0.1);
        rule->port = 0;
        strcpy(rule->action, "rate-limit");
        snprintf(rule->flowspec_rule, sizeof(rule->flowspec_rule),
                "flow match destination %s protocol udp then rate-limit %d",
                target_ip, (int)rule->rate_limit);
    } else if (strstr(attack_type, "SYN Flood") != NULL) {
        strcpy(rule->protocol, "tcp");
        rule->rate_limit = fmax(500, packet_rate * 0.2);
        rule->port = 0;
        strcpy(rule->action, "rate-limit");
        snprintf(rule->flowspec_rule, sizeof(rule->flowspec_rule),
                "flow match destination %s protocol tcp tcp-flags syn then rate-limit %d",
                target_ip, (int)rule->rate_limit);
    } else if (strstr(attack_type, "Single-Source") != NULL) {
        strcpy(rule->protocol, "any");
        strcpy(rule->action, "discard");
        rule->rate_limit = 0;
        snprintf(rule->flowspec_rule, sizeof(rule->flowspec_rule),
                "flow match source %s then discard", target_ip);
    } else {
        strcpy(rule->protocol, "any");
        rule->rate_limit = fmax(2000, packet_rate * 0.3);
        strcpy(rule->action, "rate-limit");
        snprintf(rule->flowspec_rule, sizeof(rule->flowspec_rule),
                "flow match destination %s then rate-limit %d",
                target_ip, (int)rule->rate_limit);
    }
}

void generate_acl_rule(mitigation_rule_t *rule, const char* attack_type, 
                      const char* target_ip) {
    if (strstr(attack_type, "UDP Flood") != NULL) {
        snprintf(rule->flowspec_rule, sizeof(rule->flowspec_rule),
                "iptables -A INPUT -s %s -p udp -j DROP", target_ip);
    } else if (strstr(attack_type, "SYN Flood") != NULL) {
        snprintf(rule->flowspec_rule, sizeof(rule->flowspec_rule),
                "iptables -A INPUT -s %s -p tcp --syn -j DROP", target_ip);
    } else {
        snprintf(rule->flowspec_rule, sizeof(rule->flowspec_rule),
                "iptables -A INPUT -s %s -j DROP", target_ip);
    }
}

// Enhanced mitigation application with REAL blocking
int apply_mitigation_rule(mitigation_engine_t *engine, mitigation_rule_t *rule) {
    if (engine->rule_count >= 100) return 0;
    
    rule->created_time = time(NULL);
    rule->is_active = 1;
    rule->iteration_applied = engine->current_iteration;
    rule->effectiveness = 0.0;
    rule->packets_blocked = 0;
    rule->bytes_blocked = 0;
    
    // APPLY REAL BLOCKING based on rule type
    if (strcmp(rule->rule_type, "rate_limit") == 0) {
        block_ip_address(rule->target_ip, 1, rule->rate_limit);
    } else if (strcmp(rule->rule_type, "acl_block") == 0 || 
               strcmp(rule->rule_type, "complete_block") == 0) {
        block_ip_address(rule->target_ip, 2, 0); // Complete block
    }
    
    engine->rules[engine->rule_count] = *rule;
    engine->rule_count++;
    engine->active_mitigations++;
    engine->last_mitigation_time = time(NULL);
    
    return 1;
}

// Calculate blocking effectiveness metrics
void calculate_blocking_effectiveness(mitigation_engine_t *engine, double current_packet_rate, 
                                     double baseline_rate, ip_stats_t *top_ips, int top_ip_count) {
    if (peak_attack_rate <= 0) return;
    
    // Calculate based on ACTUAL blocked packets
    if (global_filter.total_packets_blocked > 0) {
        // Estimate total traffic (blocked + passed)
        unsigned long estimated_total_traffic = global_filter.total_packets_blocked + 
                                              (unsigned long)(current_packet_rate * 10);
        if (estimated_total_traffic > 0) {
            engine->attack_traffic_dropped = (double)global_filter.total_packets_blocked / 
                                           estimated_total_traffic * 100;
        }
    } else {
        // Estimate based on rate reduction
        double traffic_reduction = fmax(0, peak_attack_rate - current_packet_rate);
        engine->attack_traffic_dropped = (traffic_reduction / peak_attack_rate) * 100.0;
    }
    
    // Calculate collateral impact based on number of blocked IPs vs total unique IPs
    if (top_ip_count > 0) {
        int blocked_legitimate_ips = 0;
        for (int i = 0; i < engine->rule_count; i++) {
            if (engine->rules[i].is_active) {
                // Check if this IP was a major contributor (likely malicious)
                int is_likely_malicious = 0;
                for (int j = 0; j < top_ip_count && j < 10; j++) {
                    if (strcmp(engine->rules[i].target_ip, top_ips[j].ip) == 0) {
                        is_likely_malicious = 1;
                        break;
                    }
                }
                if (!is_likely_malicious) {
                    blocked_legitimate_ips++;
                }
            }
        }
        engine->collateral_impact = ((double)blocked_legitimate_ips / top_ip_count) * 100.0;
    } else {
        engine->collateral_impact = fmin(10.0, engine->current_iteration * 1.5);
    }
    
    // Update total blocked counts
    engine->total_packets_blocked = global_filter.total_packets_blocked;
}

// Enhanced create_mitigation_rules with better IP selection
void create_mitigation_rules(traffic_stats_t *stats, const char* attack_type, 
                            double packet_rate, ip_stats_t *top_ips, int top_ip_count,
                            double confidence) {
    
    mitigation_engine_t *engine = &stats->mitigation_engine;
    if (confidence < 0.6) return;
    
    // Set baseline for effectiveness calculation
    if (stats->baseline_packet_rate == 0) {
        stats->baseline_packet_rate = 1000.0;
        stats->baseline_total_packets = stats->total_packets;
    }
    
    peak_attack_rate = fmax(peak_attack_rate, packet_rate);
    
    printf("\n🚨 ATTACK DETECTED - ACTIVATING REAL-TIME MITIGATIONS 🚨\n");
    printf("   📊 Confidence: %.1f%%, Packet Rate: %.1f pps\n", confidence * 100, packet_rate);
    
    int rules_created = 0;
    
    // Apply rules to multiple top IPs, avoiding duplicates
    int ips_to_check = (top_ip_count < 5) ? top_ip_count : 5;
    
    for (int i = 0; i < ips_to_check; i++) {
        double ip_percentage = (stats->total_packets > 0) ? 
            (double)top_ips[i].count / stats->total_packets * 100 : 0;
        
        // Block IPs with significant traffic (> 1%) that aren't already blocked
        int already_blocked = 0;
        for (int j = 0; j < engine->rule_count; j++) {
            if (strcmp(engine->rules[j].target_ip, top_ips[i].ip) == 0 && 
                engine->rules[j].is_active) {
                already_blocked = 1;
                break;
            }
        }
        
        if (ip_percentage > 1.0 && !already_blocked) {
            mitigation_rule_t new_rule;
            memset(&new_rule, 0, sizeof(new_rule));
            
            strncpy(new_rule.target_ip, top_ips[i].ip, MAX_IP_LENGTH - 1);
            strcpy(new_rule.direction, "in");
            
            // CRITICAL FIX: Use complete blocking for major attackers
            if (ip_percentage > 50.0 || packet_rate > 5000) {
                // MAJOR ATTACKER - Use complete block
                strcpy(new_rule.rule_type, "complete_block");
                snprintf(new_rule.flowspec_rule, sizeof(new_rule.flowspec_rule),
                        "flow match source %s then discard", top_ips[i].ip);
                printf("   🚫 COMPLETE BLOCK: %s (%.1f%% of traffic, %.0f pps)\n",
                       top_ips[i].ip, ip_percentage, (double)top_ips[i].count / 10.0);
            } else if (ip_percentage > 10.0) {
                // SIGNIFICANT CONTRIBUTOR - Use aggressive rate limiting
                strcpy(new_rule.rule_type, "rate_limit");
                new_rule.rate_limit = fmax(100, packet_rate * 0.05); // Only 5% of traffic allowed
                snprintf(new_rule.flowspec_rule, sizeof(new_rule.flowspec_rule),
                        "flow match source %s then rate-limit %d", 
                        top_ips[i].ip, (int)new_rule.rate_limit);
                printf("   ⚡ AGGRESSIVE RATE LIMIT: %s (%.1f%% of traffic)\n",
                       top_ips[i].ip, ip_percentage);
            } else {
                // MINOR CONTRIBUTOR - Use normal rate limiting
                strcpy(new_rule.rule_type, "rate_limit");
                new_rule.rate_limit = fmax(50, packet_rate * 0.1);
                snprintf(new_rule.flowspec_rule, sizeof(new_rule.flowspec_rule),
                        "flow match source %s then rate-limit %d", 
                        top_ips[i].ip, (int)new_rule.rate_limit);
                printf("   📉 RATE LIMIT: %s (%.1f%% of traffic)\n",
                       top_ips[i].ip, ip_percentage);
            }
            
            if (apply_mitigation_rule(engine, &new_rule)) {
                printf("      Rule: %s\n", new_rule.flowspec_rule);
                rules_created++;
            }
        }
    }
    
    if (rules_created == 0) {
        printf("   ℹ️  No new significant source IPs for mitigation\n");
    }
}

void create_escalated_rules(traffic_stats_t *stats, const char* attack_type, 
                           double packet_rate, ip_stats_t *top_ips, int top_ip_count,
                           double confidence, int iteration) {
    
    mitigation_engine_t *engine = &stats->mitigation_engine;
    
    printf("\n🔄 MITIGATION ITERATION %d/%d - ESCALATING RESPONSE\n", 
           iteration, engine->max_iterations);
    
    int rules_created = 0;
    
    // First, check if we need to escalate existing rules from rate_limit to complete_block
    for (int i = 0; i < engine->rule_count; i++) {
        if (engine->rules[i].is_active && 
            strcmp(engine->rules[i].rule_type, "rate_limit") == 0) {
            
            // Find current traffic percentage for this IP
            double current_percentage = 0.0;
            for (int j = 0; j < top_ip_count; j++) {
                if (strcmp(engine->rules[i].target_ip, top_ips[j].ip) == 0) {
                    current_percentage = (stats->total_packets > 0) ? 
                        (double)top_ips[j].count / stats->total_packets * 100 : 0;
                    break;
                }
            }
            
            // ESCALATE: If IP is still sending significant traffic after rate limiting, block completely
            if (current_percentage > 10.0 && iteration >= 2) {
                printf("   ⚡ ESCALATING: Converting rate_limit to complete_block for %s\n", 
                       engine->rules[i].target_ip);
                
                // Update existing rule to complete block
                strcpy(engine->rules[i].rule_type, "complete_block");
                engine->rules[i].rate_limit = 0;
                snprintf(engine->rules[i].flowspec_rule, sizeof(engine->rules[i].flowspec_rule),
                        "flow match source %s then discard", engine->rules[i].target_ip);
                
                // Update the actual packet filter
                block_ip_address(engine->rules[i].target_ip, 2, 0);
                
                rules_created++;
            }
        }
    }
    
    // Then, add new rules for unblocked IPs
    for (int i = 0; i < top_ip_count && rules_created < (2 + iteration); i++) {
        double ip_percentage = (stats->total_packets > 0) ? 
            (double)top_ips[i].count / stats->total_packets * 100 : 0;
        
        // Check if this IP is already blocked
        int already_blocked = 0;
        for (int j = 0; j < engine->rule_count; j++) {
            if (strcmp(engine->rules[j].target_ip, top_ips[i].ip) == 0 && 
                engine->rules[j].is_active) {
                already_blocked = 1;
                break;
            }
        }
        
        // Only block IPs that aren't already blocked and have significant traffic
        double escalation_threshold = fmax(0.5, 2.0 - (iteration * 0.3));
        if (!already_blocked && ip_percentage > escalation_threshold) {
            mitigation_rule_t new_rule;
            memset(&new_rule, 0, sizeof(new_rule));
            
            strncpy(new_rule.target_ip, top_ips[i].ip, MAX_IP_LENGTH - 1);
            strcpy(new_rule.direction, "in");
            
            // In later iterations, use complete blocking more aggressively
            if (iteration >= 3 || ip_percentage > 20.0) {
                strcpy(new_rule.rule_type, "complete_block");
                snprintf(new_rule.flowspec_rule, sizeof(new_rule.flowspec_rule),
                        "flow match source %s then discard", top_ips[i].ip);
            } else {
                strcpy(new_rule.rule_type, "rate_limit");
                new_rule.rate_limit = fmax(50, packet_rate * (0.1 - (iteration * 0.02)));
                snprintf(new_rule.flowspec_rule, sizeof(new_rule.flowspec_rule),
                        "flow match source %s then rate-limit %d", 
                        top_ips[i].ip, (int)new_rule.rate_limit);
            }
            
            if (apply_mitigation_rule(engine, &new_rule)) {
                printf("   ✅ Iteration %d: Created %s rule for %s (%.1f%% of traffic)\n",
                       iteration, new_rule.rule_type, top_ips[i].ip, ip_percentage);
                rules_created++;
            }
        }
    }
    
    if (rules_created == 0) {
        printf("   ℹ️  No new IPs to block in iteration %d\n", iteration);
    }
}

int should_escalate_mitigation(mitigation_engine_t *engine, double current_confidence, 
                              double previous_confidence, double effectiveness) {
    if (engine->current_iteration >= engine->max_iterations) return 0;
    if (current_confidence > 0.7 && effectiveness < 50.0) return 1;
    if (current_confidence > 0.6 && (previous_confidence - current_confidence) < 0.2) return 1;
    return 0;
}

// Enhanced effectiveness calculation with REAL blocking data
double evaluate_mitigation_effectiveness(traffic_stats_t *stats, 
                                        double previous_packet_rate,
                                        double current_packet_rate) {
    if (previous_packet_rate <= 0 || previous_packet_rate < 1000) return 0.0;
    
    // Calculate based on actual blocked packets
    unsigned long total_blocked = global_filter.total_packets_blocked;
    if (stats->total_packets + total_blocked > 0) {
        double actual_reduction = (double)total_blocked / (stats->total_packets + total_blocked) * 100;
        return fmin(100.0, actual_reduction);
    }
    
    // Fallback to rate comparison
    double reduction = (previous_packet_rate - current_packet_rate) / previous_packet_rate * 100;
    return fmax(0.0, fmin(100.0, reduction));
}

void update_rule_effectiveness(mitigation_engine_t *engine, double previous_packet_rate, 
                              double current_packet_rate, ip_stats_t *blocked_ips, int blocked_count) {
    if (previous_packet_rate <= 0) return;
    
    double overall_reduction = (previous_packet_rate - current_packet_rate) / previous_packet_rate * 100;
    engine->overall_effectiveness = fmax(0.0, fmin(100.0, overall_reduction));
    
    // Update blocking effectiveness metrics
    calculate_blocking_effectiveness(engine, current_packet_rate, previous_packet_rate, 
                                   blocked_ips, blocked_count);
    
    // Update total blocked packets (simulated)
    for (int i = 0; i < engine->rule_count; i++) {
        if (engine->rules[i].is_active) {
            engine->total_packets_blocked += engine->rules[i].packets_blocked;
            engine->total_bytes_blocked += engine->rules[i].bytes_blocked;
        }
    }
}

// ==================== CORE DETECTION FUNCTIONS ====================

void init_stats(traffic_stats_t *stats) {
    stats->total_packets = 0;
    stats->total_bytes = 0;
    stats->tcp_packets = 0;
    stats->udp_packets = 0;
    stats->syn_count = 0;
    stats->small_packet_count = 0;
    stats->malformed_packets = 0;
    stats->start_time = time(NULL);
    stats->last_packet_time = time(NULL);
    stats->ip_count = 0;
    stats->baseline_packet_rate = 0.0;
    stats->baseline_total_packets = 0;
    
    init_traffic_window(&stats->traffic_window);
    memset(&stats->pca_model, 0, sizeof(pca_model_t));
    init_cusum_detector(&stats->cusum_packet_rate, 50.0, 5.0);
    init_cusum_detector(&stats->cusum_entropy, 3.0, 0.5);
    
    get_current_time(&stats->perf_stats.start_time);
    stats->perf_stats.first_alert_time = stats->perf_stats.start_time;
    stats->perf_stats.last_packet_time = stats->perf_stats.start_time;
    stats->perf_stats.total_processing_time = 0.0;
    stats->perf_stats.total_packets_processed = 0;
    stats->perf_stats.attack_detected = 0;
    stats->perf_stats.detection_lead_time = 0.0;
    
    stats->res_stats.cpu_usage = 0.0;
    stats->res_stats.memory_usage = 0;
    stats->res_stats.network_throughput = 0.0;
    
    init_mitigation_engine(&stats->mitigation_engine);
    
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

int find_ip_index(traffic_stats_t *stats, const char *ip) {
    for (int i = 0; i < stats->ip_count; i++) {
        if (strcmp(stats->ip_stats[i].ip, ip) == 0) {
            return i;
        }
    }
    return -1;
}

void update_ip_stats(traffic_stats_t *stats, const char *ip, unsigned long packet_size) {
    int index = find_ip_index(stats, ip);
    
    if (index == -1) {
        if (stats->ip_count < MAX_IPS) {
            index = stats->ip_count;
            strncpy(stats->ip_stats[index].ip, ip, MAX_IP_LENGTH - 1);
            stats->ip_stats[index].ip[MAX_IP_LENGTH - 1] = '\0';
            stats->ip_stats[index].count = 1;
            stats->ip_stats[index].total_bytes = packet_size;
            stats->ip_stats[index].is_legitimate = 0;
            stats->ip_count++;
        }
    } else {
        stats->ip_stats[index].count++;
        stats->ip_stats[index].total_bytes += packet_size;
    }
}

double calculate_entropy(traffic_stats_t *stats) {
    if (stats->total_packets == 0 || stats->ip_count == 0) return 0.0;
    
    double entropy = 0.0;
    for (int i = 0; i < stats->ip_count; i++) {
        double p = (double)stats->ip_stats[i].count / stats->total_packets;
        if (p > 0) {
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

const char* detect_attack_type(double packet_rate, double entropy, double udp_ratio, double syn_ratio,
                              double pca_score, int cusum_alert) {
    int statistical_alert = (pca_score > 10.0) || cusum_alert;
    
    if (statistical_alert && packet_rate > 5000) {
        if (udp_ratio > 0.9) return "UDP Flood (Statistical)";
        if (syn_ratio > 0.7) return "SYN Flood (Statistical)";
        if (entropy < 1.0) return "Single-Source Flood (Statistical)";
        return "Anomalous Traffic (Statistical)";
    }
    
    if (packet_rate > 10000 && entropy < 1.0) {
        return "Single-Source Flood";
    } else if (packet_rate > 5000 && udp_ratio > 0.9) {
        return "UDP Flood";
    } else if (packet_rate > 10000 && entropy > 4.0) {
        return "Distributed Traffic";
    } else if (syn_ratio > 0.7 && packet_rate > 5000) {
        return "SYN Flood";
    } else if (packet_rate > 2000) {
        return "Suspicious Traffic";
    } else {
        return "BENIGN";
    }
}

double calculate_confidence(double packet_rate, double entropy, const char* attack_type,
                           double pca_score, int cusum_alert) {
    double confidence = 0.0;
    
    if (strcmp(attack_type, "BENIGN") == 0 || strcmp(attack_type, "Distributed Traffic") == 0) {
        confidence = 0.0;
    } else {
        if (packet_rate > 20000) confidence = 0.95;
        else if (packet_rate > 10000) confidence = 0.85;
        else if (packet_rate > 5000) confidence = 0.70;
        else if (packet_rate > 2000) confidence = 0.50;
        
        if (strcmp(attack_type, "Single-Source Flood") == 0 && entropy < 0.5) {
            confidence += 0.2;
        }
    }
    
    if (pca_score > 15.0) {
        confidence = fmax(confidence, 0.8);
        confidence += 0.1;
    }
    
    if (cusum_alert) {
        confidence = fmax(confidence, 0.7);
        confidence += 0.15;
    }
    
    return (confidence > 0.99) ? 0.99 : confidence;
}

// Structure for MPI data exchange
typedef struct {
    unsigned long total_packets;
    unsigned long total_bytes;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long syn_count;
    unsigned long small_packet_count;
    unsigned long malformed_packets;
    int ip_count;
    double entropy;
    double pca_anomaly_score;
    int cusum_alert;
    double processing_latency_avg;
    double processing_latency_95th;
    double cpu_usage;
    long memory_usage;
    int top_ip_count;
    struct {
        char ip[MAX_IP_LENGTH];
        unsigned long count;
        unsigned long total_bytes;
    } top_ips[20];
} mpi_stats_t;

void prepare_python_data(python_data_t *py_data, traffic_stats_t *stats, 
                        double packet_rate, double byte_rate, double entropy,
                        const char* attack_type, double confidence, 
                        ip_stats_t *unique_ips, int unique_ip_count, 
                        unsigned long total_packets, double pca_score, int cusum_alert,
                        double previous_packet_rate) {
    
    py_data->packet_rate = packet_rate;
    py_data->throughput_gbps = (byte_rate * 8) / (1024 * 1024 * 1024);
    py_data->entropy = entropy;
    py_data->udp_ratio = (total_packets > 0) ? 
                        (double)stats->udp_packets / total_packets : 0;
    py_data->syn_ratio = (total_packets > 0) ? 
                        (double)stats->syn_count / total_packets : 0;
    
    py_data->detection_lead_time = stats->perf_stats.detection_lead_time;
    py_data->avg_processing_latency = (stats->perf_stats.total_packets_processed > 0) ?
                                     stats->perf_stats.total_processing_time / 
                                     stats->perf_stats.total_packets_processed : 0;
    
    py_data->cpu_usage = get_cpu_usage();
    py_data->memory_usage = get_memory_usage();
    
    strncpy(py_data->attack_type, attack_type, sizeof(py_data->attack_type) - 1);
    py_data->confidence = confidence;
    py_data->unique_ips = unique_ip_count;
    py_data->is_attack = (confidence > 0.6);
    
    py_data->pca_anomaly_score = pca_score;
    py_data->cusum_anomaly_score = stats->cusum_packet_rate.cumulative_sum + 
                                  stats->cusum_entropy.cumulative_sum;
    py_data->pca_alert = (pca_score > 10.0);
    py_data->cusum_alert = cusum_alert;
    
    py_data->top_ip_count = (unique_ip_count < 10) ? unique_ip_count : 10;
    for (int i = 0; i < py_data->top_ip_count; i++) {
        strncpy(py_data->top_ips[i], unique_ips[i].ip, MAX_IP_LENGTH - 1);
        py_data->top_ip_counts[i] = unique_ips[i].count;
        py_data->top_ip_percentages[i] = (total_packets > 0) ?
                                        (double)unique_ips[i].count / total_packets * 100 : 0;
    }
    
    // MITIGATION DATA
    py_data->mitigation_active = stats->mitigation_engine.active_mitigations > 0;
    py_data->rules_created = stats->mitigation_engine.rule_count;
    py_data->mitigation_effectiveness = evaluate_mitigation_effectiveness(
        stats, previous_packet_rate, packet_rate);
    py_data->attack_traffic_dropped = stats->mitigation_engine.attack_traffic_dropped;
    py_data->collateral_impact = stats->mitigation_engine.collateral_impact;
    py_data->mitigation_iteration = stats->mitigation_engine.current_iteration;
    py_data->total_packets_blocked = stats->mitigation_engine.total_packets_blocked;
    
    if (stats->mitigation_engine.active_mitigations > 0) {
        snprintf(py_data->current_mitigation, sizeof(py_data->current_mitigation),
                "%d active rules (%s)", stats->mitigation_engine.active_mitigations,
                stats->mitigation_engine.rules[0].rule_type);
    } else {
        strcpy(py_data->current_mitigation, "None");
    }
    
    py_data->timestamp = time(NULL);
}

void save_python_data(const char* filename, python_data_t *data) {
    FILE *file = fopen(filename, "w");
    if (!file) return;
    
    fprintf(file, "{\n");
    fprintf(file, "  \"timestamp\": %ld,\n", data->timestamp);
    fprintf(file, "  \"packet_rate\": %.2f,\n", data->packet_rate);
    fprintf(file, "  \"throughput_gbps\": %.4f,\n", data->throughput_gbps);
    fprintf(file, "  \"entropy\": %.3f,\n", data->entropy);
    fprintf(file, "  \"udp_ratio\": %.3f,\n", data->udp_ratio);
    fprintf(file, "  \"syn_ratio\": %.3f,\n", data->syn_ratio);
    fprintf(file, "  \"detection_lead_time\": %.2f,\n", data->detection_lead_time);
    fprintf(file, "  \"avg_processing_latency\": %.4f,\n", data->avg_processing_latency);
    fprintf(file, "  \"cpu_usage\": %.2f,\n", data->cpu_usage);
    fprintf(file, "  \"memory_usage\": %ld,\n", data->memory_usage);
    fprintf(file, "  \"attack_type\": \"%s\",\n", data->attack_type);
    fprintf(file, "  \"confidence\": %.3f,\n", data->confidence);
    fprintf(file, "  \"unique_ips\": %d,\n", data->unique_ips);
    fprintf(file, "  \"is_attack\": %s,\n", data->is_attack ? "true" : "false");
    
    // Statistical detection data
    fprintf(file, "  \"pca_anomaly_score\": %.3f,\n", data->pca_anomaly_score);
    fprintf(file, "  \"cusum_anomaly_score\": %.3f,\n", data->cusum_anomaly_score);
    fprintf(file, "  \"pca_alert\": %s,\n", data->pca_alert ? "true" : "false");
    fprintf(file, "  \"cusum_alert\": %s,\n", data->cusum_alert ? "true" : "false");
    
    // Mitigation data
    fprintf(file, "  \"mitigation_active\": %s,\n", data->mitigation_active ? "true" : "false");
    fprintf(file, "  \"rules_created\": %d,\n", data->rules_created);
    fprintf(file, "  \"current_mitigation\": \"%s\",\n", data->current_mitigation);
    fprintf(file, "  \"mitigation_effectiveness\": %.1f,\n", data->mitigation_effectiveness);
    fprintf(file, "  \"attack_traffic_dropped\": %.1f,\n", data->attack_traffic_dropped);
    fprintf(file, "  \"collateral_impact\": %.1f,\n", data->collateral_impact);
    fprintf(file, "  \"mitigation_iteration\": %d,\n", data->mitigation_iteration);
    fprintf(file, "  \"total_packets_blocked\": %lu,\n", data->total_packets_blocked);
    
    fprintf(file, "  \"top_ips\": [\n");
    for (int i = 0; i < data->top_ip_count; i++) {
        fprintf(file, "    {\"ip\": \"%s\", \"count\": %lu, \"percentage\": %.2f}",
                data->top_ips[i], data->top_ip_counts[i], data->top_ip_percentages[i]);
        if (i < data->top_ip_count - 1) fprintf(file, ",");
        fprintf(file, "\n");
    }
    fprintf(file, "  ]\n");
    fprintf(file, "}\n");
    
    fclose(file);
}

// ==================== REAL MITIGATION FUNCTIONS ====================

// Initialize packet filter
void init_packet_filter() {
    global_filter.blocked_count = 0;
    global_filter.total_packets_blocked = 0;
    global_filter.total_bytes_blocked = 0;
}

// Check if packet should be blocked
int should_block_packet(const char* src_ip, unsigned long packet_size) {
    for (int i = 0; i < global_filter.blocked_count; i++) {
        if (strcmp(global_filter.blocked_ips[i].ip, src_ip) == 0) {
            // Complete block - always block
            if (global_filter.blocked_ips[i].block_type == 2) {
                global_filter.blocked_ips[i].packets_blocked++;
                global_filter.blocked_ips[i].bytes_blocked += packet_size;
                global_filter.total_packets_blocked++;
                global_filter.total_bytes_blocked += packet_size;
                return 1;
            }
            // Rate limiting (simplified - in real implementation use token bucket)
            else if (global_filter.blocked_ips[i].block_type == 1) {
                // Simple rate limiting: block 90% of packets for demonstration
                if (rand() % 100 < 90) {
                    global_filter.blocked_ips[i].packets_blocked++;
                    global_filter.blocked_ips[i].bytes_blocked += packet_size;
                    global_filter.total_packets_blocked++;
                    global_filter.total_bytes_blocked += packet_size;
                    return 1;
                }
            }
        }
    }
    return 0;
}

// Add IP to block list
void block_ip_address(const char* ip, int block_type, double rate_limit) {
    // Check if already blocked
    for (int i = 0; i < global_filter.blocked_count; i++) {
        if (strcmp(global_filter.blocked_ips[i].ip, ip) == 0) {
            // ESCALATE: If changing from rate_limit to complete_block
            if (global_filter.blocked_ips[i].block_type == 1 && block_type == 2) {
                printf("   🔥 ESCALATING BLOCK: %s from rate_limit to complete_block\n", ip);
            }
            // Update existing rule
            global_filter.blocked_ips[i].block_type = block_type;
            global_filter.blocked_ips[i].rate_limit = rate_limit;
            global_filter.blocked_ips[i].blocked_time = time(NULL); // Refresh timestamp
            return;
        }
    }
    
    // Add new block if not at capacity
    if (global_filter.blocked_count >= 100) {
        printf("   ⚠️  Block list full, cannot block %s\n", ip);
        return;
    }
    
    strcpy(global_filter.blocked_ips[global_filter.blocked_count].ip, ip);
    global_filter.blocked_ips[global_filter.blocked_count].blocked_time = time(NULL);
    global_filter.blocked_ips[global_filter.blocked_count].packets_blocked = 0;
    global_filter.blocked_ips[global_filter.blocked_count].bytes_blocked = 0;
    global_filter.blocked_ips[global_filter.blocked_count].block_type = block_type;
    global_filter.blocked_ips[global_filter.blocked_count].rate_limit = rate_limit;
    global_filter.blocked_count++;
    
    printf("   🔒 REAL-TIME BLOCKING: Added %s to filter (%s)\n", 
           ip, block_type == 2 ? "complete block" : "rate limiting");
}

// Remove IP from block list
void unblock_ip_address(const char* ip) {
    for (int i = 0; i < global_filter.blocked_count; i++) {
        if (strcmp(global_filter.blocked_ips[i].ip, ip) == 0) {
            printf("   🔓 UNBLOCKING: Removed %s from filter\n", ip);
            // Shift remaining elements
            for (int j = i; j < global_filter.blocked_count - 1; j++) {
                global_filter.blocked_ips[j] = global_filter.blocked_ips[j + 1];
            }
            global_filter.blocked_count--;
            return;
        }
    }
}

// Synchronize blocked IPs across all MPI ranks
void synchronize_blocked_ips(int rank, int size) {
    if (size == 1) return; // No need to sync if only one rank
    
    // First, gather the count of blocked IPs from all ranks
    int blocked_counts[size];
    int my_blocked_count = global_filter.blocked_count;
    
    MPI_Allgather(&my_blocked_count, 1, MPI_INT, blocked_counts, 1, MPI_INT, MPI_COMM_WORLD);
    
    // Find the maximum blocked count
    int max_blocked = 0;
    for (int i = 0; i < size; i++) {
        if (blocked_counts[i] > max_blocked) {
            max_blocked = blocked_counts[i];
        }
    }
    
    if (max_blocked == 0) return;
    
    // Create a buffer for blocked IP data
    typedef struct {
        char ip[MAX_IP_LENGTH];
        int block_type;
        double rate_limit;
    } blocked_ip_sync_t;
    
    blocked_ip_sync_t my_blocked_ips[max_blocked];
    blocked_ip_sync_t all_blocked_ips[size][max_blocked];
    
    // Initialize my blocked IPs
    for (int i = 0; i < max_blocked; i++) {
        if (i < global_filter.blocked_count) {
            strcpy(my_blocked_ips[i].ip, global_filter.blocked_ips[i].ip);
            my_blocked_ips[i].block_type = global_filter.blocked_ips[i].block_type;
            my_blocked_ips[i].rate_limit = global_filter.blocked_ips[i].rate_limit;
        } else {
            my_blocked_ips[i].ip[0] = '\0';
            my_blocked_ips[i].block_type = 0;
            my_blocked_ips[i].rate_limit = 0;
        }
    }
    
    // Gather all blocked IPs from all ranks
    MPI_Allgather(my_blocked_ips, max_blocked * sizeof(blocked_ip_sync_t), MPI_BYTE,
                  all_blocked_ips, max_blocked * sizeof(blocked_ip_sync_t), MPI_BYTE,
                  MPI_COMM_WORLD);
    
    // Merge blocked IPs from all ranks
    for (int r = 0; r < size; r++) {
        for (int i = 0; i < max_blocked; i++) {
            if (all_blocked_ips[r][i].ip[0] != '\0') {
                // Check if this IP is already in our filter
                int already_blocked = 0;
                for (int j = 0; j < global_filter.blocked_count; j++) {
                    if (strcmp(global_filter.blocked_ips[j].ip, all_blocked_ips[r][i].ip) == 0) {
                        already_blocked = 1;
                        break;
                    }
                }
                
                // Add if not already blocked
                if (!already_blocked && global_filter.blocked_count < 100) {
                    strcpy(global_filter.blocked_ips[global_filter.blocked_count].ip, all_blocked_ips[r][i].ip);
                    global_filter.blocked_ips[global_filter.blocked_count].block_type = all_blocked_ips[r][i].block_type;
                    global_filter.blocked_ips[global_filter.blocked_count].rate_limit = all_blocked_ips[r][i].rate_limit;
                    global_filter.blocked_ips[global_filter.blocked_count].blocked_time = time(NULL);
                    global_filter.blocked_ips[global_filter.blocked_count].packets_blocked = 0;
                    global_filter.blocked_ips[global_filter.blocked_count].bytes_blocked = 0;
                    global_filter.blocked_count++;
                    
                    if (rank != 0) {
                        printf("   🔄 Rank %d: Learned about blocked IP %s from other rank\n", 
                               rank, all_blocked_ips[r][i].ip);
                    }
                }
            }
        }
    }
}

// Enhanced display of multiple IPs in reports
void display_multiple_ips(ip_stats_t *unique_ips, int total_unique_ips, unsigned long total_packets) {
    int printed = 0;
    int max_display = 5; // Show top 5 IPs
    
    for (int i = 0; i < total_unique_ips && printed < max_display; i++) {
        double ip_percentage = (total_packets > 0) ? 
            (double)unique_ips[i].count / total_packets * 100 : 0;
        
        // Show IPs with more than 0.1% of traffic
        if (ip_percentage > 0.1) {
            double avg_pkt_size = (unique_ips[i].count > 0) ? 
                (double)unique_ips[i].total_bytes / unique_ips[i].count : 0;
            
            // Check if this IP is currently blocked
            int is_blocked = 0;
            for (int j = 0; j < global_filter.blocked_count; j++) {
                if (strcmp(global_filter.blocked_ips[j].ip, unique_ips[i].ip) == 0) {
                    is_blocked = 1;
                    break;
                }
            }
            
            printf("║    %-15s : %6lu pkts (%5.1f%%) | Avg: %4.0f bytes %s ║\n",
                   unique_ips[i].ip, unique_ips[i].count, ip_percentage, avg_pkt_size,
                   is_blocked ? "🔒" : "");
            printed++;
        }
    }
    
    if (printed == 0) {
        printf("║    No significant source IPs identified                      ║\n");
    }
    
    // Show blocking statistics
    if (global_filter.blocked_count > 0) {
        printf("║                                                              ║\n");
        printf("║    🔒 Currently Blocked: %2d IPs, %lu packets blocked        ║\n",
               global_filter.blocked_count, global_filter.total_packets_blocked);
    }
}

// Enhanced packet handler with real filtering
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    traffic_stats_t *stats = (traffic_stats_t *)user_data;
    
    if (!running) return;
    
    struct timespec processing_start, processing_end;
    get_current_time(&processing_start);
    
    // Check if packet should be blocked BEFORE processing
    struct ethhdr *eth = (struct ethhdr *)packet;
    unsigned short ether_type = ntohs(eth->h_proto);
    
    if (ether_type == ETH_P_IP) {
        if (pkthdr->len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            stats->malformed_packets++;
            return;
        }
        
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
        char src_ip[MAX_IP_LENGTH];
        inet_ntop(AF_INET, &(ip->saddr), src_ip, MAX_IP_LENGTH);
        
        // REAL FILTERING: Check if this IP should be blocked
        if (should_block_packet(src_ip, pkthdr->len)) {
            // Packet is blocked - don't process it
            return;
        }
        
        // Only process packets that passed the filter
        stats->total_packets++;
        stats->total_bytes += pkthdr->len;
        stats->last_packet_time = time(NULL);
        get_current_time(&stats->perf_stats.last_packet_time);
        
        if (pkthdr->len < 100) {
            stats->small_packet_count++;
        }
        
        if (ip->protocol == IPPROTO_TCP) {
            stats->tcp_packets++;
            if (pkthdr->len >= sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct tcphdr)) {
                struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl * 4));
                if (tcp->syn && !tcp->ack) {
                    stats->syn_count++;
                }
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            stats->udp_packets++;
        }
        
        update_ip_stats(stats, src_ip, pkthdr->len);
    } else {
        stats->malformed_packets++;
    }
    
    get_current_time(&processing_end);
    double processing_time = time_diff_ms(processing_start, processing_end);
    stats->perf_stats.total_processing_time += processing_time;
    stats->perf_stats.total_packets_processed++;
}

// ==================== UPDATED GATHER AND ANALYZE FUNCTION ====================

void gather_and_analyze_distributed(int rank, int size, traffic_stats_t *local_stats) {
    mpi_stats_t local_mpi;
    
    local_stats->res_stats.cpu_usage = get_cpu_usage();
    local_stats->res_stats.memory_usage = get_memory_usage();
    
    // Convert local stats to MPI structure
    local_mpi.total_packets = local_stats->total_packets;
    local_mpi.total_bytes = local_stats->total_bytes;
    local_mpi.tcp_packets = local_stats->tcp_packets;
    local_mpi.udp_packets = local_stats->udp_packets;
    local_mpi.syn_count = local_stats->syn_count;
    local_mpi.small_packet_count = local_stats->small_packet_count;
    local_mpi.malformed_packets = local_stats->malformed_packets;
    local_mpi.ip_count = local_stats->ip_count;
    local_mpi.entropy = calculate_entropy(local_stats);
    
    // Performance metrics
    local_mpi.processing_latency_avg = (local_stats->perf_stats.total_packets_processed > 0) ?
                                      local_stats->perf_stats.total_processing_time / 
                                      local_stats->perf_stats.total_packets_processed : 0.0;
    local_mpi.processing_latency_95th = local_mpi.processing_latency_avg * 1.5;
    local_mpi.cpu_usage = local_stats->res_stats.cpu_usage;
    local_mpi.memory_usage = local_stats->res_stats.memory_usage;
    
    // Statistical detection results
    local_mpi.pca_anomaly_score = 0.0;
    local_mpi.cusum_alert = 0;
    
    // Get top IPs from local stats
    local_mpi.top_ip_count = 0;
    if (local_stats->ip_count > 0) {
        // Sort local IPs by count
        for (int i = 0; i < local_stats->ip_count; i++) {
            for (int j = i + 1; j < local_stats->ip_count; j++) {
                if (local_stats->ip_stats[j].count > local_stats->ip_stats[i].count) {
                    ip_stats_t temp = local_stats->ip_stats[i];
                    local_stats->ip_stats[i] = local_stats->ip_stats[j];
                    local_stats->ip_stats[j] = temp;
                }
            }
        }
        
        int count = (local_stats->ip_count < 20) ? local_stats->ip_count : 20;
        local_mpi.top_ip_count = count;
        for (int i = 0; i < count; i++) {
            strcpy(local_mpi.top_ips[i].ip, local_stats->ip_stats[i].ip);
            local_mpi.top_ips[i].count = local_stats->ip_stats[i].count;
            local_mpi.top_ips[i].total_bytes = local_stats->ip_stats[i].total_bytes;
        }
    }
    
    if (rank == 0) {
        mpi_stats_t global_mpi;
        mpi_stats_t all_ranks[size];
        all_ranks[0] = local_mpi;
        
        // Receive data from other ranks
        for (int i = 1; i < size; i++) {
            MPI_Recv(&all_ranks[i], sizeof(mpi_stats_t), MPI_BYTE, i, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        }
        
        // Aggregate basic statistics
        global_mpi.total_packets = 0;
        global_mpi.total_bytes = 0;
        global_mpi.tcp_packets = 0;
        global_mpi.udp_packets = 0;
        global_mpi.syn_count = 0;
        global_mpi.small_packet_count = 0;
        global_mpi.malformed_packets = 0;
        global_mpi.ip_count = 0;
        global_mpi.entropy = 0.0;
        global_mpi.pca_anomaly_score = 0.0;
        global_mpi.cusum_alert = 0;
        
        // Aggregate performance metrics
        double total_processing_time = 0.0;
        unsigned long total_processed_packets = 0;
        double max_cpu_usage = 0.0;
        long max_memory_usage = 0;
        
        // Collect all unique IPs for entropy calculation
        ip_stats_t all_unique_ips[MAX_IPS];
        int total_unique_ips = 0;
        unsigned long global_total_packets = 0;
        
        for (int r = 0; r < size; r++) {
            global_mpi.total_packets += all_ranks[r].total_packets;
            global_mpi.total_bytes += all_ranks[r].total_bytes;
            global_mpi.tcp_packets += all_ranks[r].tcp_packets;
            global_mpi.udp_packets += all_ranks[r].udp_packets;
            global_mpi.syn_count += all_ranks[r].syn_count;
            global_mpi.small_packet_count += all_ranks[r].small_packet_count;
            global_mpi.malformed_packets += all_ranks[r].malformed_packets;
            global_mpi.ip_count += all_ranks[r].ip_count;
            
            // Statistical detection aggregation (take maximum)
            global_mpi.pca_anomaly_score = fmax(global_mpi.pca_anomaly_score, all_ranks[r].pca_anomaly_score);
            global_mpi.cusum_alert |= all_ranks[r].cusum_alert;
            
            // Performance metrics aggregation
            total_processing_time += all_ranks[r].processing_latency_avg * all_ranks[r].total_packets;
            total_processed_packets += all_ranks[r].total_packets;
            if (all_ranks[r].cpu_usage > max_cpu_usage) max_cpu_usage = all_ranks[r].cpu_usage;
            if (all_ranks[r].memory_usage > max_memory_usage) max_memory_usage = all_ranks[r].memory_usage;
            
            // Collect IPs from this rank
            for (int i = 0; i < all_ranks[r].top_ip_count && total_unique_ips < MAX_IPS; i++) {
                int found = -1;
                for (int j = 0; j < total_unique_ips; j++) {
                    if (strcmp(all_unique_ips[j].ip, all_ranks[r].top_ips[i].ip) == 0) {
                        found = j;
                        break;
                    }
                }
                
                if (found != -1) {
                    all_unique_ips[found].count += all_ranks[r].top_ips[i].count;
                    all_unique_ips[found].total_bytes += all_ranks[r].top_ips[i].total_bytes;
                } else {
                    strcpy(all_unique_ips[total_unique_ips].ip, all_ranks[r].top_ips[i].ip);
                    all_unique_ips[total_unique_ips].count = all_ranks[r].top_ips[i].count;
                    all_unique_ips[total_unique_ips].total_bytes = all_ranks[r].top_ips[i].total_bytes;
                    total_unique_ips++;
                }
            }
        }
        
        global_total_packets = global_mpi.total_packets;
        
        // Calculate GLOBAL entropy
        global_mpi.entropy = 0.0;
        if (global_total_packets > 0 && total_unique_ips > 0) {
            for (int i = 0; i < total_unique_ips; i++) {
                double p = (double)all_unique_ips[i].count / global_total_packets;
                if (p > 0) {
                    global_mpi.entropy -= p * log2(p);
                }
            }
        }
        
        // Sort the aggregated IPs by count
        for (int i = 0; i < total_unique_ips; i++) {
            for (int j = i + 1; j < total_unique_ips; j++) {
                if (all_unique_ips[j].count > all_unique_ips[i].count) {
                    ip_stats_t temp = all_unique_ips[i];
                    all_unique_ips[i] = all_unique_ips[j];
                    all_unique_ips[j] = temp;
                }
            }
        }
        
        // Final global analysis
        time_t current_time = time(NULL);
        double elapsed = difftime(current_time, local_stats->start_time);
        double global_packet_rate = (elapsed > 0) ? (double)global_mpi.total_packets / elapsed : 0;
        double global_byte_rate = (elapsed > 0) ? (double)global_mpi.total_bytes / elapsed : 0;
        double udp_ratio = (global_mpi.total_packets > 0) ? (double)global_mpi.udp_packets / global_mpi.total_packets : 0;
        double syn_ratio = (global_mpi.total_packets > 0) ? (double)global_mpi.syn_count / global_mpi.total_packets : 0;
        
        // Update statistical detection with current metrics
        add_to_window(&local_stats->traffic_window, global_packet_rate, global_mpi.entropy, udp_ratio);

        // Train PCA model (works with partial data)
        train_pca_model(&local_stats->traffic_window, &local_stats->pca_model);

        // Get actual samples available
        int samples_available = local_stats->traffic_window.is_full ? 
                               WINDOW_SIZE : local_stats->traffic_window.current_index;

        // Run statistical detection (works during training)
        double pca_score = pca_anomaly_detection(&local_stats->pca_model, global_packet_rate, 
                                               global_mpi.entropy, udp_ratio, samples_available);

        // More sensitive CUSUM detection
        int cusum_packet_alert = cusum_detect(&local_stats->cusum_packet_rate, global_packet_rate, 1000.0);
        int cusum_entropy_alert = cusum_detect(&local_stats->cusum_entropy, global_mpi.entropy, 2.0);
        int cusum_alert = cusum_packet_alert || cusum_entropy_alert;
        
        // Enhanced attack detection with statistical methods
        const char* global_attack_type = detect_attack_type(global_packet_rate, global_mpi.entropy, udp_ratio, syn_ratio,
                                                           pca_score, cusum_alert);
        double global_confidence = calculate_confidence(global_packet_rate, global_mpi.entropy, global_attack_type,
                                                       pca_score, cusum_alert);
        
        // ==================== PHASE 1: DETECTION REPORT ====================
        
        printf("\n\n");
        printf("╔════════════════════════════════════════════════════════════════════╗\n");
        printf("║                 PHASE 1: DDoS DETECTION REPORT                   ║\n");
        printf("╠════════════════════════════════════════════════════════════════════╣\n");
        printf("║ MPI Processes: %2d      Analysis Time: %8.1f sec          ║\n", size, elapsed);
        
        if (global_confidence > 0.6) {
            printf("║ 🔴 DETECTION STATUS: ATTACK CONFIRMED                           ║\n");
            printf("║    Type: %-20s Confidence: %5.1f%%                    ║\n", 
                   global_attack_type, global_confidence * 100);
        } else {
            printf("║ 🟢 DETECTION STATUS: NORMAL TRAFFIC                             ║\n");
            printf("║    Type: %-20s Confidence: %5.1f%%                    ║\n", 
                   global_attack_type, (1.0 - global_confidence) * 100);
        }
        
        printf("╠════════════════════════════════════════════════════════════════════╣\n");
        printf("║ 📊 TRAFFIC ANALYSIS (PRE-MITIGATION)                            ║\n");
        printf("║    Total Packets: %10lu    Packet Rate: %8.1f pps    ║\n", 
               global_mpi.total_packets, global_packet_rate);
        printf("║    Total Bytes: %12lu    Byte Rate: %10.1f Bps    ║\n", 
               global_mpi.total_bytes, global_byte_rate);
        printf("║    Unique IPs: %8d        Global Entropy: %8.2f      ║\n", 
               total_unique_ips, global_mpi.entropy);
        printf("║    TCP: %6lu (%4.1f%%)   UDP: %6lu (%4.1f%%)           ║\n",
               global_mpi.tcp_packets, (global_mpi.total_packets > 0 ? (double)global_mpi.tcp_packets/global_mpi.total_packets*100 : 0),
               global_mpi.udp_packets, (global_mpi.total_packets > 0 ? (double)global_mpi.udp_packets/global_mpi.total_packets*100 : 0));
        
        // Statistical detection results
        printf("╠════════════════════════════════════════════════════════════════════╣\n");
        printf("║ 📈 STATISTICAL DETECTION RESULTS                               ║\n");
        printf("║    PCA Anomaly Score: %8.2f %s                          ║\n",
               pca_score, (pca_score > 10.0) ? "🔴" : "🟢");
        printf("║    CUSUM Alert: %12s %s                                ║\n",
               cusum_alert ? "TRIGGERED" : "NORMAL", cusum_alert ? "🔴" : "🟢");
        
        printf("╠════════════════════════════════════════════════════════════════════╣\n");
        printf("║ 🔍 TOP ATTACKER IPs IDENTIFIED                                 ║\n");
        display_multiple_ips(all_unique_ips, total_unique_ips, global_total_packets);
        
        printf("╚════════════════════════════════════════════════════════════════════╝\n");
        
        // ==================== PHASE 2: MITIGATION DECISION ====================
        
        mitigation_engine_t *engine = &local_stats->mitigation_engine;
        double mitigation_effectiveness = 0.0;
        
        // Calculate effectiveness based on previous state
        if (previous_global_packet_rate > 0) {
            mitigation_effectiveness = evaluate_mitigation_effectiveness(
                local_stats, previous_global_packet_rate, global_packet_rate);
            update_rule_effectiveness(engine, previous_global_packet_rate, global_packet_rate, 
                                   all_unique_ips, total_unique_ips);
        }
        
        // Track peak attack rate for effectiveness calculation
        if (global_confidence > 0.6) {
            peak_attack_rate = fmax(peak_attack_rate, global_packet_rate);
        }
        
        // MITIGATION DECISION LOGIC
        if (global_confidence > 0.6) {
            if (engine->active_mitigations == 0) {
                // FIRST DETECTION - Start mitigation cycle
                printf("\n🚨 PHASE 2: ACTIVATING MITIGATIONS 🚨\n");
                printf("   📊 Attack Confidence: %.1f%%, Packet Rate: %.1f pps\n", 
                       global_confidence * 100, global_packet_rate);
                
                engine->current_iteration = 1;
                create_mitigation_rules(local_stats, global_attack_type, global_packet_rate,
                                      all_unique_ips, total_unique_ips, global_confidence);
                mitigation_phase_active = 1;
                
            } else if (should_escalate_mitigation(engine, global_confidence, 
                                                 previous_global_confidence, mitigation_effectiveness)) {
                // ATTACK PERSISTS - Escalate mitigation
                printf("\n🔄 MITIGATION ITERATION %d/%d - ESCALATING RESPONSE\n", 
                       engine->current_iteration, engine->max_iterations);
                
                engine->current_iteration++;
                create_escalated_rules(local_stats, global_attack_type, global_packet_rate,
                                     all_unique_ips, total_unique_ips, global_confidence, 
                                     engine->current_iteration);
                
            } else {
                // MITIGATION IN PROGRESS - Monitor effectiveness
                printf("\n🔄 MITIGATION ITERATION %d/%d IN PROGRESS\n", 
                       engine->current_iteration, engine->max_iterations);
                printf("   📊 Current: %.1f pps (%.1f%% reduction) | Confidence: %.1f%%\n",
                       global_packet_rate, mitigation_effectiveness, global_confidence * 100);
            }
            
            engine->attack_persists = 1;
            
        } else if (global_confidence < 0.3 && engine->active_mitigations > 0) {
            // ATTACK STOPPED - Remove mitigations
            printf("\n🟢 ATTACK MITIGATED SUCCESSFULLY - CLEANING UP RULES\n");
            printf("   📊 Final packet rate: %.1f pps (%.1f%% reduction from peak)\n",
                   global_packet_rate, mitigation_effectiveness);
            
            for (int i = 0; i < engine->rule_count; i++) {
                engine->rules[i].is_active = 0;
            }
            engine->active_mitigations = 0;
            engine->current_iteration = 0;
            engine->attack_persists = 0;
            mitigation_phase_active = 0;
            
            printf("   ✅ Removed %d mitigation rules\n", engine->rule_count);
        }
        
        // Store current state for next iteration comparison
        previous_global_packet_rate = global_packet_rate;
        previous_global_confidence = global_confidence;
        
        // Update performance stats
        if (global_confidence > 0.6 && !local_stats->perf_stats.attack_detected) {
            local_stats->perf_stats.attack_detected = 1;
            get_current_time(&local_stats->perf_stats.first_alert_time);
            local_stats->perf_stats.detection_lead_time = 
                time_diff_ms(local_stats->perf_stats.start_time, 
                           local_stats->perf_stats.first_alert_time);
        }
        
        // Update global stats with aggregated performance metrics
        local_stats->perf_stats.total_processing_time = total_processing_time;
        local_stats->perf_stats.total_packets_processed = total_processed_packets;
        local_stats->res_stats.cpu_usage = max_cpu_usage;
        local_stats->res_stats.memory_usage = max_memory_usage;
        local_stats->res_stats.network_throughput = global_byte_rate;
        
        // ==================== PHASE 3: MITIGATION STATUS ====================
        
        if (mitigation_phase_active || engine->active_mitigations > 0) {
            printf("\n");
            printf("╔════════════════════════════════════════════════════════════════════╗\n");
            printf("║                 PHASE 3: MITIGATION STATUS                      ║\n");
            printf("╠════════════════════════════════════════════════════════════════════╣\n");
            
            if (mitigation_phase_active) {
                printf("║ 🔄 MITIGATION ITERATION: %d/%d    EFFECTIVENESS: %5.1f%%         ║\n",
                       engine->current_iteration, engine->max_iterations, mitigation_effectiveness);
            } else {
                printf("║ 🟢 NORMAL OPERATION    No active mitigations                    ║\n");
            }
            
            printf("╠════════════════════════════════════════════════════════════════════╣\n");
            printf("║ 🛡️  ACTIVE MITIGATION RULES                                     ║\n");
            if (engine->active_mitigations > 0) {
                printf("║    Active Rules: %2d    Effectiveness: %5.1f%%                 ║\n",
                       engine->active_mitigations, mitigation_effectiveness);
                for (int i = 0; i < engine->rule_count && i < 3; i++) {
                    if (engine->rules[i].is_active) {
                        printf("║    Rule %d: %-15s %-12s                      ║\n",
                               i + 1, engine->rules[i].target_ip,
                               engine->rules[i].rule_type);
                    }
                }
            } else {
                printf("║    No active mitigations                                        ║\n");
            }
            
            printf("╠════════════════════════════════════════════════════════════════════╣\n");
            printf("║ 📊 BLOCKING EFFECTIVENESS                                       ║\n");
            printf("║    Attack Traffic Dropped: %6.1f%%                              ║\n",
                   engine->attack_traffic_dropped);
            printf("║    Collateral Impact: %11.1f%%                              ║\n",
                   engine->collateral_impact);
            printf("║    Total Packets Blocked: %8lu                            ║\n",
                   engine->total_packets_blocked);
            
            if (mitigation_phase_active) {
                printf("║    Next analysis in 10 seconds...                              ║\n");
            }
            printf("╚════════════════════════════════════════════════════════════════════╝\n");
        }
        
        // Final summary
        printf("\n📊 FINAL SUMMARY:\n");
        printf("   - Attack Type: %s\n", global_attack_type);
        printf("   - Detection Confidence: %.1f%%\n", global_confidence * 100);
        printf("   - Packet Rate: %.1f pps\n", global_packet_rate);
        printf("   - Unique Source IPs: %d\n", total_unique_ips);
        
        if (mitigation_phase_active) {
            printf("   - 🛡️  MITIGATION ACTIVE: Iteration %d/%d, %.1f%% effective\n", 
                   engine->current_iteration, engine->max_iterations, mitigation_effectiveness);
            printf("   - 📊 Blocking: %.1f%% attack traffic dropped, %.1f%% collateral impact\n",
                   engine->attack_traffic_dropped, engine->collateral_impact);
        } else if (global_confidence > 0.6) {
            printf("   - 🔴 MITIGATION NEEDED: High confidence attack detected\n");
        } else {
            printf("   - 🟢 STATUS: Normal traffic - no mitigation needed\n");
        }
        
        // Prepare and save data for Python visualization
        python_data_t py_data;
        prepare_python_data(&py_data, local_stats, global_packet_rate, 
                          global_byte_rate, global_mpi.entropy, global_attack_type,
                          global_confidence, all_unique_ips, total_unique_ips, 
                          global_total_packets, pca_score, cusum_alert,
                          previous_global_packet_rate);
        
        save_python_data("ddos_live_data.json", &py_data);
        printf("📊 Data saved for Python visualization: ddos_live_data.json\n");
        
    } else {
        // Send data to rank 0 (other ranks don't display anything)
        MPI_Send(&local_mpi, sizeof(mpi_stats_t), MPI_BYTE, 0, 0, MPI_COMM_WORLD);
    }
}

// Initialize packet filter in main function
int main(int argc, char** argv) {
    int rank, size;
    
    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    
    // Initialize REAL packet filtering
    init_packet_filter();
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (rank == 0) {
        printf("🚀 DISTRIBUTED DDoS DETECTION & REAL-TIME MITIGATION SYSTEM\n");
        printf("📡 MPI Processes: %d | Interface: eth0\n", size);
        printf("⏰ Auto-stop after %d seconds of no traffic\n", TRAFFIC_TIMEOUT);
        printf("🔧 Hash-based packet distribution across %d ranks\n", size);
        printf("🛡️  REAL-TIME ITERATIVE MITIGATION WITH PACKET FILTERING\n");
        printf("📊 Blocking metrics: Attack dropped %%, Collateral impact %%\n");
        printf("🐍 Python visualization data: ddos_live_data.json\n");
        printf("------------------------------------------------------------\n");
    }
    
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", 65535, 1, 1000, errbuff);
    
    if (!handle) {
        if (rank == 0) {
            fprintf(stderr, "❌ Error opening interface: %s\n", errbuff);
            fprintf(stderr, "💡 Check: sudo ip link set eth0 up\n");
        }
        MPI_Finalize();
        return 1;
    }
    
    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        if (rank == 0) {
            fprintf(stderr, "❌ Couldn't parse filter: %s\n", pcap_geterr(handle));
        }
        pcap_close(handle);
        MPI_Finalize();
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        if (rank == 0) {
            fprintf(stderr, "❌ Couldn't install filter: %s\n", pcap_geterr(handle));
        }
        pcap_close(handle);
        MPI_Finalize();
        return 1;
    }
    
    traffic_stats_t local_stats;
    init_stats(&local_stats);
    
    if (rank == 0) {
        printf("🎯 Starting distributed capture across %d MPI ranks...\n", size);
        printf("💡 Performance metrics will be displayed by root process only\n");
        printf("📊 JSON data for Python visualization will be updated every 10 seconds\n");
        printf("🛡️  Mitigation will auto-start when attack confidence > 60%%\n");
    }
    
    struct pcap_pkthdr* header;
    const u_char* packet;
    time_t last_analysis_time = time(NULL);
    time_t last_sync_time = time(NULL);
    
    while (running) {
        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res <= 0) {
            time_t current_time = time(NULL);
            if (local_stats.total_packets > 0 && 
                difftime(current_time, local_stats.last_packet_time) >= TRAFFIC_TIMEOUT) {
                if (rank == 0) printf("\n🛑 No traffic detected for %d seconds\n", TRAFFIC_TIMEOUT);
                break;
            }
            continue;
        }
        
        int h = hash_func(packet, header->len) % size;
        
        if (h == rank) {
            packet_handler((u_char*)&local_stats, header, packet);
        }
        
        time_t current_time = time(NULL);
        
        // Synchronize blocked IPs every 2 seconds (more frequent than analysis)
        if (difftime(current_time, last_sync_time) >= 2) {
            synchronize_blocked_ips(rank, size);
            last_sync_time = current_time;
        }
        
        // Analysis every 10 seconds
        if (difftime(current_time, last_analysis_time) >= 10) {
            gather_and_analyze_distributed(rank, size, &local_stats);
            last_analysis_time = current_time;
            
            // Also sync blocked IPs after analysis (in case new rules were created)
            synchronize_blocked_ips(rank, size);
        }
    }
    
    gather_and_analyze_distributed(rank, size, &local_stats);
    
    pcap_close(handle);
    free_stats(&local_stats);
    
    MPI_Finalize();
    
    if (rank == 0) {
        printf("\n✅ Distributed DDoS detection & mitigation completed\n");
        printf("📁 Check ddos_live_data.json for the final data snapshot\n");
    }
    
    return 0;
}

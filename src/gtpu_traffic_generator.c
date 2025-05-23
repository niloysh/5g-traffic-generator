/**
 * @file gtpu_traffic_generator.c
 * @brief Multi-threaded GTP-U traffic generator using AF_PACKET.
 *
 * - Loads TEID-to-app/QFI mapping and traffic profiles from JSON
 * - Sends variable-size GTP-U packets with QFI extension
 * - Uses 4 threads; TEIDs divided evenly
 * - Reports per-QFI PPS and Mbps
 *
 * Example configs: config/profiles.json, config/teid_map.json
 *
 * Usage:
 *   sudo ./build/gtpu_traffic_generator <profiles.json> <teid_map.json> <iface>
 * <src_ip> <dst_ip>
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <jansson.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <math.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define NUM_THREADS 4
#define MAX_PKT_SIZE 1514
#define GTPU_PORT 2152
#define ETHER_TYPE 0x0800
#define GTPU_PAD_LEN 3
#define GTPU_QFI_EXT_LEN 5
#define GTPU_HEADER_LEN (8 + GTPU_PAD_LEN + GTPU_QFI_EXT_LEN)
#define MAX_INNER_PAYLOAD 1150 // stops working at 1200, why? MTU is 1500
#define MIN(a, b) ((a) < (b) ? (a) : (b))

volatile int stop = 0;
void handle_signal(int sig) {
  (void)sig;
  stop = 1;
}

typedef struct {
  atomic_ulong pps;
  atomic_ulong bytes;
} qfi_stat_t;

qfi_stat_t global_qfi_stats[64];

typedef struct {
  double min;
  double avg;
  double max;
} gap_stats_t;

typedef struct {
  uint32_t teid;
  const char *app;
  json_t *profile;
  int qfi;
  uint64_t next_send_ns;
  double next_gap_ms;
  int next_pkt_size;
  json_t *burst_pps_array; // JSON array of burst_trace.pps
  double baseline_pps;     // computed from profile
  uint64_t start_time_ns;  // when this TEID started
} teid_entry_t;

typedef struct {
  teid_entry_t *teids;
  int num_teids;
  int thread_id;
  int sockfd;
  struct sockaddr_ll sa;
  uint8_t src_mac[6];
  uint8_t dst_mac[6];
  const char *src_ip;
  const char *dst_ip;
  unsigned int rand_seed;
} thread_arg_t;

uint64_t now_nsec() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

uint16_t checksum(uint16_t *buf, int nwords) {
  uint32_t sum = 0;
  for (; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (uint16_t)(~sum);
}

void nanosleep_until(uint64_t target_ns) {
  uint64_t now = now_nsec();
  if (target_ns > now) {
    struct timespec ts = {.tv_sec = (target_ns - now) / 1000000000,
                          .tv_nsec = (target_ns - now) % 1000000000};
    nanosleep(&ts, NULL);
  }
}

double sample_gap(gap_stats_t *stats, unsigned int *seed) {
  double lambda = 1.0 / stats->avg;
  double gap = -log(1.0 - ((double)rand_r(seed) / RAND_MAX)) / lambda;
  return fmin(fmax(gap, stats->min), stats->max);
}

int sample_packet_size(json_t *buckets, unsigned int *seed) {
  int sizes[] = {80, 200, 450, 750, 1050, 1350};
  int weights[6], total = 0;
  const char *keys[] = {"<100",    "100-299",  "300-599",
                        "600-899", "900-1199", ">=1200"};
  for (int i = 0; i < 6; i++) {
    json_t *val = json_object_get(buckets, keys[i]);
    weights[i] = val ? json_integer_value(val) : 0;
    total += weights[i];
  }
  if (total == 0)
    return 200;
  int r = rand_r(seed) % total, cumulative = 0;
  for (int i = 0; i < 6; i++) {
    cumulative += weights[i];
    if (r < cumulative)
      return sizes[i];
  }
  return 200;
}

int build_inner_packet(uint8_t *buf, int payload_len) {
  struct iphdr *ip = (struct iphdr *)buf;
  struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct iphdr));
  char *payload = (char *)(buf + sizeof(struct iphdr) + sizeof(struct udphdr));
  memset(payload, 'A', payload_len);

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
  ip->id = htons(1234);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = inet_addr("10.0.0.1");
  ip->daddr = inet_addr("8.8.8.8");
  ip->check = 0;
  ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr) / 2);

  udp->source = htons(12345);
  udp->dest = htons(54321);
  udp->len = htons(sizeof(struct udphdr) + payload_len);
  udp->check = 0;

  return sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
}

void build_gtpu_packet(uint8_t *packet, const uint8_t *src_mac,
                       const uint8_t *dst_mac, const char *src_ip,
                       const char *dst_ip, uint32_t teid, uint8_t qfi,
                       const uint8_t *inner_payload, int inner_len) {
  struct ethhdr *eth = (struct ethhdr *)packet;
  struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
  struct udphdr *udp =
      (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
  uint8_t *gtpu = packet + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                  sizeof(struct udphdr);
  uint8_t *payload_dst = gtpu + GTPU_HEADER_LEN;

  memcpy(payload_dst, inner_payload, inner_len);
  int total_payload_len = GTPU_HEADER_LEN + inner_len;

  gtpu[0] = 0x34;
  gtpu[1] = 0xFF;
  uint16_t gtpu_len = htons(inner_len + GTPU_PAD_LEN + GTPU_QFI_EXT_LEN);
  memcpy(&gtpu[2], &gtpu_len, 2);
  uint32_t teid_n = htonl(teid);
  memcpy(&gtpu[4], &teid_n, 4);
  gtpu[8] = gtpu[9] = gtpu[10] = 0x00;
  gtpu[11] = 0x85;
  gtpu[12] = 0x01;
  gtpu[13] = (0x1 << 4);
  gtpu[14] = qfi & 0x3F;
  gtpu[15] = 0x00;

  memcpy(eth->h_dest, dst_mac, 6);
  memcpy(eth->h_source, src_mac, 6);
  eth->h_proto = htons(ETH_P_IP);

  ip->ihl = 5;
  ip->version = 4;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = inet_addr(src_ip);
  ip->daddr = inet_addr(dst_ip);
  ip->tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct udphdr) + total_payload_len);
  ip->check = 0;
  ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr) / 2);

  udp->source = htons(12345);
  udp->dest = htons(GTPU_PORT);
  udp->len = htons(sizeof(struct udphdr) + total_payload_len);
  udp->check = 0;
}

void *sender_thread(void *arg) {
  thread_arg_t *t = (thread_arg_t *)arg;
  uint8_t packet[MAX_PKT_SIZE];
  uint8_t inner_buf[1200];

  while (!stop) {
    uint64_t now = now_nsec();
    uint64_t next_wake_ns = UINT64_MAX;
    bool sent_any = false;

    for (int i = 0; i < t->num_teids; i++) {
      teid_entry_t *entry = &t->teids[i];
      if (entry->next_send_ns > now) {
        next_wake_ns = MIN(next_wake_ns, entry->next_send_ns);
        continue;
      }

      // Sample variable payload length and build inner packet accordingly
      entry->next_pkt_size =
          MIN(sample_packet_size(
                  json_object_get(
                      json_object_get(json_object_get(entry->profile, "stats"),
                                      "packet_size"),
                      "buckets"),
                  &t->rand_seed),
              MAX_INNER_PAYLOAD);

      int inner_len = build_inner_packet(inner_buf, entry->next_pkt_size);
      build_gtpu_packet(packet, t->src_mac, t->dst_mac, t->src_ip, t->dst_ip,
                        entry->teid, entry->qfi, inner_buf, inner_len);

      ssize_t sent =
          sendto(t->sockfd, packet,
                 sizeof(struct ethhdr) + sizeof(struct iphdr) +
                     sizeof(struct udphdr) + GTPU_HEADER_LEN + inner_len,
                 0, (struct sockaddr *)&t->sa, sizeof(t->sa));
      if (sent < 0)
        perror("sendto failed");

      __atomic_fetch_add((unsigned long *)&global_qfi_stats[entry->qfi].pps, 1,
                         __ATOMIC_RELAXED);
      __atomic_fetch_add((unsigned long *)&global_qfi_stats[entry->qfi].bytes,
                         sent, __ATOMIC_RELAXED);
      sent_any = true;

      // Sample nominal gap from profile
      json_t *gap_stats_json = json_object_get(
          json_object_get(entry->profile, "stats"), "inter_packet_gap_ms");
      gap_stats_t gaps = {
          .min = json_number_value(json_object_get(gap_stats_json, "min")),
          .avg = json_number_value(json_object_get(gap_stats_json, "avg")),
          .max = json_number_value(json_object_get(gap_stats_json, "max"))};
      entry->next_gap_ms = sample_gap(&gaps, &t->rand_seed);

      // Modulate gap based on burst_trace
      if (entry->burst_pps_array) {
        uint64_t elapsed_sec = (now - entry->start_time_ns) / 1000000000ULL;
        size_t trace_len = json_array_size(entry->burst_pps_array);
        if (trace_len > 0) {
          size_t idx = elapsed_sec % trace_len;
          json_t *pps_val = json_array_get(entry->burst_pps_array, idx);
          if (json_is_integer(pps_val)) {
            double burst_pps = json_integer_value(pps_val);
            double baseline = fmax(entry->baseline_pps, 1.0);
            double multiplier = burst_pps / baseline;
            multiplier = fmin(fmax(multiplier, 0.2), 5.0); // clamp
            entry->next_gap_ms /= multiplier;
          }
        }
      }

      entry->next_send_ns = now + (uint64_t)(entry->next_gap_ms * 1e6);
      next_wake_ns = MIN(next_wake_ns, entry->next_send_ns);
    }

    if (!sent_any && next_wake_ns != UINT64_MAX) {
      nanosleep_until(next_wake_ns);
    }
  }
  return NULL;
}

void print_human_pps(char *buf, size_t len, unsigned long pps) {
  if (pps >= 1000000) {
    snprintf(buf, len, "%.2fM", pps / 1e6);
  } else if (pps >= 1000) {
    snprintf(buf, len, "%.2fK", pps / 1e3);
  } else {
    snprintf(buf, len, "%lu", pps);
  }
}

void *reporter_thread(void *arg) {
  (void)arg;
  while (!stop) {
    sleep(5);
    unsigned long total_pps = 0;
    unsigned long total_bytes = 0;

    printf("\n[Stats] Active QFIs:\n");
    printf("  QFI |   PPS   |  Mbps\n");
    printf("------+---------+--------\n");

    for (int qfi = 0; qfi < 64; qfi++) {
      unsigned long pps = atomic_exchange(&global_qfi_stats[qfi].pps, 0);
      unsigned long bytes = atomic_exchange(&global_qfi_stats[qfi].bytes, 0);

      if (pps > 0) {
        double mbps = (bytes * 8.0) / (5 * 1e6);
        char pps_buf[16];
        unsigned long pps_per_sec = pps / 5;
        print_human_pps(pps_buf, sizeof(pps_buf), pps_per_sec);
        printf("  %3d | %7s | %6.2f\n", qfi, pps_buf, mbps);
        total_pps += pps;
        total_bytes += bytes;
      }
    }

    if (total_pps > 0) {
      double total_mbps = (total_bytes * 8.0) / (5 * 1e6);
      char total_pps_buf[16];
      print_human_pps(total_pps_buf, sizeof(total_pps_buf), total_pps / 5);
      printf("Total: %7s PPS | %6.2f Mbps\n", total_pps_buf, total_mbps);
    } else {
      printf("No active QFIs in this interval.\n");
    }
  }

  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc != 6) {
    fprintf(stderr,
            "Usage: %s <profiles.json> <teid_map.json> <interface> <src_ip> "
            "<dst_ip>\n",
            argv[0]);
    return 1;
  }

  signal(SIGINT, handle_signal);

  json_error_t error;
  json_t *profiles = json_load_file(argv[1], 0, &error);
  if (!profiles) {
    fprintf(stderr, "Error loading profiles JSON: %s\n", error.text);
    return 1;
  }

  json_t *map_root = json_load_file(argv[2], 0, &error);
  if (!map_root) {
    fprintf(stderr, "Error loading teid_map JSON: %s\n", error.text);
    json_decref(profiles);
    return 1;
  }

  const char *iface = argv[3], *src_ip = argv[4], *dst_ip = argv[5];
  json_t *teids = json_object_get(map_root, "teids");
  int total_teids = json_array_size(teids);
  int teids_per_thread = (total_teids + NUM_THREADS - 1) / NUM_THREADS;

  pthread_t threads[NUM_THREADS];
  pthread_t reporter;
  thread_arg_t args[NUM_THREADS];

  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  struct ifreq ifr;
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  ioctl(sockfd, SIOCGIFINDEX, &ifr);
  int ifindex = ifr.ifr_ifindex;
  ioctl(sockfd, SIOCGIFHWADDR, &ifr);
  uint8_t src_mac[6];
  memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
  uint8_t dst_mac[6] = {0xe4, 0x1d, 0x2d, 0x09, 0xa8, 0x30};

  struct sockaddr_ll sa = {0};
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = ifindex;
  sa.sll_halen = ETH_ALEN;
  memcpy(sa.sll_addr, dst_mac, 6);

  for (int t = 0; t < NUM_THREADS; t++) {
    args[t] =
        (thread_arg_t){.sockfd = sockfd,
                       .sa = sa,
                       .thread_id = t,
                       .src_ip = src_ip,
                       .dst_ip = dst_ip,
                       .rand_seed = (unsigned int)time(NULL) ^ (t * 7919)};
    memcpy(args[t].src_mac, src_mac, 6);
    memcpy(args[t].dst_mac, dst_mac, 6);

    int start = t * teids_per_thread;
    int end = (start + teids_per_thread > total_teids)
                  ? total_teids
                  : start + teids_per_thread;
    args[t].num_teids = end - start;
    args[t].teids = calloc(args[t].num_teids, sizeof(teid_entry_t));

    for (int i = start; i < end; i++) {
      json_t *teid_obj = json_array_get(teids, i);
      const char *app = json_string_value(json_object_get(teid_obj, "app"));
      json_t *profile = json_object_get(profiles, app);
      int qfi = json_integer_value(json_object_get(profile, "qfi"));

      json_t *stats = json_object_get(profile, "stats");
      json_t *burst_trace = json_object_get(stats, "burst_trace");
      json_t *pps_array =
          burst_trace ? json_object_get(burst_trace, "pps") : NULL;

      double baseline_pps = 1.0;
      if (pps_array && json_is_array(pps_array)) {
        uint64_t sum = 0;
        size_t len = json_array_size(pps_array);
        for (size_t k = 0; k < len; k++) {
          json_t *val = json_array_get(pps_array, k);
          if (json_is_integer(val))
            sum += json_integer_value(val);
        }
        if (len > 0)
          baseline_pps = (double)sum / len;
      }

      args[t].teids[i - start] = (teid_entry_t){
          .teid = json_integer_value(json_object_get(teid_obj, "teid")),
          .app = app,
          .profile = profile,
          .qfi = qfi,
          .next_send_ns = 0,
          .burst_pps_array = pps_array,
          .baseline_pps = baseline_pps,
          .start_time_ns = now_nsec()};

      args[t].teids[i - start].next_pkt_size = sample_packet_size(
          json_object_get(
              json_object_get(json_object_get(profile, "stats"), "packet_size"),
              "buckets"),
          &args[t].rand_seed);
    }

    pthread_create(&threads[t], NULL, sender_thread, &args[t]);
  }

  pthread_create(&reporter, NULL, reporter_thread, NULL);

  for (int t = 0; t < NUM_THREADS; t++) {
    pthread_join(threads[t], NULL);
    free(args[t].teids);
  }
  pthread_join(reporter, NULL);

  close(sockfd);
  json_decref(profiles);
  json_decref(map_root);
  return 0;
}

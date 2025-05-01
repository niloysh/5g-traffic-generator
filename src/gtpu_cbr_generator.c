/**
 * @file gtpu_cbr_generator.c
 * @brief Sends high-rate, multi-threaded GTP-U traffic at a constant bit rate
 * with a fixed payload size.
 *
 * @author Niloy Saha
 * @email niloysaha.ns@gmail.com
 *
 * @details Creates multiple threads to generate and send GTP-U encapsulated
 * UDP packets at a constant rate via a specified interface. Each thread sends
 * with a target packet rate and uses a specific TEID/QFI. The inner UDP payload
 * has a fixed size. Periodically displays sending statistics.
 *
 * @usage sudo ./gtpu_cbr_generator
 *
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define INTERFACE "enp2s0f0"
#define SRC_IP "192.168.44.13"
#define DST_IP "192.168.44.18"
#define DST_MAC "\xe4\x1d\x2d\x09\xa8\x30"
#define NUM_THREADS 8
#define STATS_INTERVAL 5
#define MAX_PKT_SIZE 1514
#define TARGET_PPS 100000 // Per-thread packet rate limit

#define GTPU_PORT 2152
#define GTPU_BASE_LEN 8
#define GTPU_PAD_LEN 3
#define GTPU_QFI_EXT_LEN 5
#define GTPU_TOTAL_HDR_LEN (GTPU_BASE_LEN + GTPU_PAD_LEN + GTPU_QFI_EXT_LEN)
#define INNER_PAYLOAD_SIZE 1024

uint32_t TEIDs[] = {0x100, 0x101, 0x102, 0x103};
uint8_t QFIs[] = {5, 6, 7, 8};
int NUM_SLICES = 4;

volatile int stop = 0;
pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
uint64_t total_packets = 0;
uint64_t total_bytes = 0;

void handle_signal(int sig) {
  (void)sig;
  stop = 1;
}

unsigned short checksum(unsigned short *buf, int nwords) {
  unsigned long sum = 0;
  for (; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

int build_inner_packet(uint8_t *buf, const char *src_ip, const char *dst_ip,
                       uint16_t sport, uint16_t dport) {
  struct iphdr *ip = (struct iphdr *)buf;
  struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct iphdr));
  char *payload = (char *)(buf + sizeof(struct iphdr) + sizeof(struct udphdr));

  memset(payload, 'A', INNER_PAYLOAD_SIZE);

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct udphdr) + INNER_PAYLOAD_SIZE);
  ip->id = htons(1234);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = inet_addr(src_ip);
  ip->daddr = inet_addr(dst_ip);
  ip->check = 0;
  ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr) / 2);

  udp->source = htons(sport);
  udp->dest = htons(dport);
  udp->len = htons(sizeof(struct udphdr) + INNER_PAYLOAD_SIZE);
  udp->check = 0;

  return sizeof(struct iphdr) + sizeof(struct udphdr) + INNER_PAYLOAD_SIZE;
}

int build_gtpu_packet(uint8_t *packet, const uint8_t *src_mac,
                      const uint8_t *dst_mac, const char *outer_src_ip,
                      const char *outer_dst_ip, const uint8_t *inner_payload,
                      int inner_len, uint32_t teid, uint8_t qfi) {
  struct ethhdr *eth = (struct ethhdr *)packet;
  struct iphdr *ip_outer = (struct iphdr *)(packet + sizeof(struct ethhdr));
  struct udphdr *udp_outer =
      (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
  uint8_t *gtpu_hdr = (uint8_t *)(packet + sizeof(struct ethhdr) +
                                  sizeof(struct iphdr) + sizeof(struct udphdr));
  uint8_t *payload_dst = gtpu_hdr + GTPU_TOTAL_HDR_LEN;

  gtpu_hdr[0] = 0x34;
  gtpu_hdr[1] = 0xFF;
  uint16_t gtpu_len = htons(inner_len + GTPU_PAD_LEN + GTPU_QFI_EXT_LEN);
  memcpy(&gtpu_hdr[2], &gtpu_len, 2);
  uint32_t teid_net = htonl(teid);
  memcpy(&gtpu_hdr[4], &teid_net, 4);
  gtpu_hdr[8] = gtpu_hdr[9] = gtpu_hdr[10] = 0x00;
  gtpu_hdr[11] = 0x85;
  gtpu_hdr[12] = 0x01;
  gtpu_hdr[13] = (0x1 << 4);
  gtpu_hdr[14] = qfi & 0x3F;
  gtpu_hdr[15] = 0x00;

  memcpy(payload_dst, inner_payload, inner_len);
  int total_payload_len = GTPU_TOTAL_HDR_LEN + inner_len;

  memcpy(eth->h_dest, dst_mac, 6);
  memcpy(eth->h_source, src_mac, 6);
  eth->h_proto = htons(ETH_P_IP);

  ip_outer->ihl = 5;
  ip_outer->version = 4;
  ip_outer->tos = 0;
  ip_outer->tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct udphdr) + total_payload_len);
  ip_outer->id = htons(0);
  ip_outer->frag_off = 0;
  ip_outer->ttl = 64;
  ip_outer->protocol = IPPROTO_UDP;
  ip_outer->saddr = inet_addr(outer_src_ip);
  ip_outer->daddr = inet_addr(outer_dst_ip);
  ip_outer->check = 0;
  ip_outer->check =
      checksum((unsigned short *)ip_outer, sizeof(struct iphdr) / 2);

  udp_outer->source = htons(12345);
  udp_outer->dest = htons(GTPU_PORT);
  udp_outer->len = htons(sizeof(struct udphdr) + total_payload_len);
  udp_outer->check = 0;

  return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) +
         total_payload_len;
}

void *sender_thread(void *arg) {
  int thread_id = *(int *)arg;
  free(arg);

  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sockfd < 0) {
    perror("socket");
    pthread_exit(NULL);
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ - 1);
  ioctl(sockfd, SIOCGIFINDEX, &ifr);
  int ifindex = ifr.ifr_ifindex;
  ioctl(sockfd, SIOCGIFHWADDR, &ifr);
  uint8_t src_mac[6];
  memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
  uint8_t dst_mac[6] = DST_MAC;

  struct sockaddr_ll sa = {0};
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = ifindex;
  sa.sll_halen = ETH_ALEN;
  memcpy(sa.sll_addr, dst_mac, 6);

  uint8_t packet[MAX_PKT_SIZE];
  uint8_t inner_buf[512];

  struct timespec next_send;
  clock_gettime(CLOCK_MONOTONIC, &next_send);
  const long nanos_per_pkt = 1000000000L / TARGET_PPS;

  while (!stop) {
    int slice_id = thread_id % NUM_SLICES;
    uint32_t teid = TEIDs[slice_id];
    uint8_t qfi = QFIs[slice_id];

    int inner_len = build_inner_packet(inner_buf, "10.0.0.1", "8.8.8.8",
                                       5000 + thread_id, 6000 + thread_id);
    int pkt_len = build_gtpu_packet(packet, src_mac, dst_mac, SRC_IP, DST_IP,
                                    inner_buf, inner_len, teid, qfi);
    ssize_t sent =
        sendto(sockfd, packet, pkt_len, 0, (struct sockaddr *)&sa, sizeof(sa));
    if (sent < 0) {
      perror("sendto");
      break;
    }

    __sync_fetch_and_add(&total_packets, 1);
    __sync_fetch_and_add(&total_bytes, sent);

    next_send.tv_nsec += nanos_per_pkt;
    if (next_send.tv_nsec >= 1000000000L) {
      next_send.tv_nsec -= 1000000000L;
      next_send.tv_sec += 1;
    }
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_send, NULL);
  }

  close(sockfd);
  pthread_exit(NULL);
}

int main(void) {
  signal(SIGINT, handle_signal);

  pthread_t threads[NUM_THREADS];
  printf("Starting sender with %d threads on %s...\n", NUM_THREADS, INTERFACE);

  for (int i = 0; i < NUM_THREADS; i++) {
    int *arg = malloc(sizeof(*arg));
    *arg = i;
    pthread_create(&threads[i], NULL, sender_thread, arg);
  }

  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);
  uint64_t last_packets = 0;
  uint64_t last_bytes = 0;

  while (!stop) {
    sleep(STATS_INTERVAL);
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed =
        (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;

    uint64_t pkts = total_packets;
    uint64_t bytes = total_bytes;
    double pps = (pkts - last_packets) / elapsed;
    double mbps = ((bytes - last_bytes) * 8.0) / (elapsed * 1e6);

    printf("[+%.1fs] Sent: %lu pkts — %.0f pps — %.2f Mbps\n", elapsed, pkts,
           pps, mbps);

    last_packets = pkts;
    last_bytes = bytes;
    clock_gettime(CLOCK_MONOTONIC, &start);
  }

  printf("Stopping...\n");
  for (int i = 0; i < NUM_THREADS; i++)
    pthread_join(threads[i], NULL);

  printf("Done. Total packets sent: %lu\n", total_packets);
  return 0;
}

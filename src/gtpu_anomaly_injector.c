/** @file: gtpu_anomaly_injector.c
 * @brief: Parameterized GTP-U CBR traffic generator for anomaly injection
 *
 * @example: sudo ./gtpu_anomaly_injector --interface enp2s0f0 --src-ip
 * 192.168.44.13 --dst-ip 192.168.44.18 --teids 0x2000,0x2001 --qfis 1,2 --pps
 * 300000 --duration 3 --num-threads 2
 */

 #define _GNU_SOURCE
 #include <arpa/inet.h>
 #include <fcntl.h>
 #include <getopt.h>
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
 
 #define MAX_PKT_SIZE 1514
 #define GTPU_PORT 2152
 #define GTPU_BASE_LEN 8
 #define GTPU_PAD_LEN 3
 #define GTPU_QFI_EXT_LEN 5
 #define GTPU_TOTAL_HDR_LEN (GTPU_BASE_LEN + GTPU_PAD_LEN + GTPU_QFI_EXT_LEN)
 #define INNER_PAYLOAD_SIZE 1024
 
 volatile int stop = 0;
 pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
 uint64_t total_packets = 0;
 uint64_t total_bytes = 0;
 
 char *interface = NULL;
 char *src_ip = NULL;
 char *dst_ip = NULL;
 uint8_t dst_mac[6] = {0xe4, 0x1d, 0x2d, 0x09, 0xa8, 0x30};
 uint32_t *teids = NULL;
 uint8_t *qfis = NULL;
 int num_slices = 0;
 int num_threads = 1;
 double duration = 5.0;
 int pps = 100000;
 int pps_per_thread = 0;
 
 void handle_signal(int sig) { (void)sig; stop = 1; }
 
 unsigned short checksum(unsigned short *buf, int nwords) {
   unsigned long sum = 0;
   for (; nwords > 0; nwords--) sum += *buf++;
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   return (unsigned short)(~sum);
 }
 
 int build_inner_packet(uint8_t *buf, const char *src_ip, const char *dst_ip,
                        uint16_t sport, uint16_t dport);
 int build_gtpu_packet(uint8_t *packet, const uint8_t *src_mac,
                       const uint8_t *dst_mac, const char *outer_src_ip,
                       const char *outer_dst_ip, const uint8_t *inner_payload,
                       int inner_len, uint32_t teid, uint8_t qfi);
 
 void *sender_thread(void *arg) {
   int thread_id = *(int *)arg;
   free(arg);
 
   cpu_set_t cpuset;
   CPU_ZERO(&cpuset);
   CPU_SET(thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
   pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
 
   int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   if (sockfd < 0) { perror("socket"); pthread_exit(NULL); }
 
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
   ioctl(sockfd, SIOCGIFINDEX, &ifr);
   int ifindex = ifr.ifr_ifindex;
   ioctl(sockfd, SIOCGIFHWADDR, &ifr);
   uint8_t src_mac[6];
   memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
 
   struct sockaddr_ll sa = {0};
   sa.sll_family = AF_PACKET;
   sa.sll_protocol = htons(ETH_P_ALL);
   sa.sll_ifindex = ifindex;
   sa.sll_halen = ETH_ALEN;
   memcpy(sa.sll_addr, dst_mac, 6);
 
   uint8_t packet[MAX_PKT_SIZE];
   uint8_t inner_buf[512];
   struct timespec start, now, next_send;
 
   clock_gettime(CLOCK_MONOTONIC, &start);
   clock_gettime(CLOCK_MONOTONIC, &next_send);
   const long nanos_per_pkt = 1000000000L / pps_per_thread;
 
   while (!stop) {
     clock_gettime(CLOCK_MONOTONIC, &now);
     double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
     if (elapsed >= duration) break;
 
     int slice_id = thread_id % num_slices;
     uint32_t teid = teids[slice_id];
     uint8_t qfi = qfis[slice_id];
 
     int inner_len = build_inner_packet(inner_buf, src_ip, dst_ip, 5000 + thread_id, 6000 + thread_id);
     int pkt_len = build_gtpu_packet(packet, src_mac, dst_mac, src_ip, dst_ip,
                                     inner_buf, inner_len, teid, qfi);
     ssize_t sent = sendto(sockfd, packet, pkt_len, 0, (struct sockaddr *)&sa, sizeof(sa));
     if (sent < 0) break;
 
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
   return NULL;
 }
 
 void parse_list(const char *arg, uint32_t **arr_u32, uint8_t **arr_u8,
                 int *count, int is_u32) {
   char *copy = strdup(arg);
   char *token = strtok(copy, ",");
   int capacity = 16, size = 0;
   uint32_t *u32 = malloc(capacity * sizeof(uint32_t));
   uint8_t *u8 = malloc(capacity * sizeof(uint8_t));
   while (token) {
     if (size >= capacity) {
       capacity *= 2;
       u32 = realloc(u32, capacity * sizeof(uint32_t));
       u8 = realloc(u8, capacity * sizeof(uint8_t));
     }
     if (is_u32) u32[size++] = strtoul(token, NULL, 0);
     else u8[size++] = atoi(token);
     token = strtok(NULL, ",");
   }
   *count = size;
   if (is_u32) *arr_u32 = u32;
   else *arr_u8 = u8;
   free(copy);
 }
 
 int main(int argc, char *argv[]) {
   signal(SIGINT, handle_signal);
 
   static struct option long_opts[] = {
       {"interface", required_argument, 0, 'i'},
       {"src-ip", required_argument, 0, 's'},
       {"dst-ip", required_argument, 0, 'd'},
       {"teids", required_argument, 0, 't'},
       {"qfis", required_argument, 0, 'q'},
       {"pps", required_argument, 0, 'p'},
       {"duration", required_argument, 0, 'D'},
       {"num-threads", required_argument, 0, 'n'},
       {0, 0, 0, 0}};
 
   int opt;
   while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
     switch (opt) {
     case 'i': interface = strdup(optarg); break;
     case 's': src_ip = strdup(optarg); break;
     case 'd': dst_ip = strdup(optarg); break;
     case 't': parse_list(optarg, &teids, NULL, &num_slices, 1); break;
     case 'q': parse_list(optarg, NULL, &qfis, &num_slices, 0); break;
     case 'p': pps = atoi(optarg); break;
     case 'D': duration = atof(optarg); break;
     case 'n': num_threads = atoi(optarg); break;
     default:
       fprintf(stderr, "Usage: %s --interface IF --src-ip IP --dst-ip IP --teids LIST --qfis LIST\n", argv[0]);
       exit(1);
     }
   }
 
   if (!interface || !src_ip || !dst_ip || !teids || !qfis || num_slices == 0) {
     fprintf(stderr, "[!] Missing required arguments.\n");
     exit(1);
   }
   if (num_threads > pps) {
     fprintf(stderr, "[!] Too many threads (%d) for global PPS %d.\n", num_threads, pps);
     exit(1);
   }
   pps_per_thread = pps / num_threads;
   if (pps_per_thread == 0) pps_per_thread = 1;
 
   pthread_t threads[num_threads];
   for (int i = 0; i < num_threads; i++) {
     int *arg = malloc(sizeof(int)); *arg = i;
     pthread_create(&threads[i], NULL, sender_thread, arg);
   }
   for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);
 
   double mbits = (total_bytes * 8.0) / 1e6;
   printf("[+] Sent %lu packets (%.2f Mbps) in %f seconds using %d threads\n",
          total_packets, mbits / duration, duration, num_threads);
   return 0;
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

int parse_mac(const char *mac_str, uint8_t *mac) {
  return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
                &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

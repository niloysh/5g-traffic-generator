#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define GTPU_PORT 2152
#define GTPU_HDR_LEN 16
#define MAX_PKT_SIZE 1600
#define MAX_FRAME_SIZE 1500
#define QFI_CHECK_INTERVAL_MS 100

uint32_t TEID = 0x1001;
uint8_t QFI = 5;
const char *QFI_FILE_PATH = NULL;

const char *SRC_MAC_STR = "a0:36:9f:ba:36:ac";
const char *DST_MAC_STR = "e4:1d:2d:09:a8:30";
const char *SRC_IP = "192.168.44.13";
const char *DST_IP = "192.168.44.18";
uint8_t SRC_MAC[6], DST_MAC[6];

int parse_mac(const char *mac_str, uint8_t *mac) {
  return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
                &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

void timespec_diff(const struct timeval *a, const struct timeval *b,
                   struct timespec *res) {
  time_t sec = a->tv_sec - b->tv_sec;
  suseconds_t usec = a->tv_usec - b->tv_usec;
  if (usec < 0) {
    sec -= 1;
    usec += 1000000;
  }
  res->tv_sec = sec;
  res->tv_nsec = usec * 1000;
}

void timespec_add(struct timespec *a, struct timespec *b,
                  struct timespec *res) {
  res->tv_sec = a->tv_sec + b->tv_sec;
  res->tv_nsec = a->tv_nsec + b->tv_nsec;
  if (res->tv_nsec >= 1000000000L) {
    res->tv_nsec -= 1000000000L;
    res->tv_sec += 1;
  }
}

void check_qfi_update() {
  static time_t last_check = 0;
  time_t now = time(NULL);
  if (!QFI_FILE_PATH || now == last_check)
    return;
  last_check = now;

  FILE *f = fopen(QFI_FILE_PATH, "r");
  if (f) {
    int new_qfi;
    if (fscanf(f, "%d", &new_qfi) == 1 && new_qfi >= 0 && new_qfi <= 63 &&
        new_qfi != QFI) {
      printf("[INFO] QFI changed from %d to %d (TEID=0x%x, file=%s)\n", QFI,
             new_qfi, TEID, QFI_FILE_PATH ? QFI_FILE_PATH : "unknown");
      QFI = (uint8_t)new_qfi;
    }
    fclose(f);
  }
}

int wrap_gtpu_packet(const uint8_t *orig, int orig_len, uint8_t *out_buf) {
  int max_inner = MAX_FRAME_SIZE -
                  (int)(sizeof(struct ether_header) + sizeof(struct iphdr) +
                        sizeof(struct udphdr) + GTPU_HDR_LEN);
  int actual_inner = orig_len > max_inner ? max_inner : orig_len;

  struct ether_header *eth = (struct ether_header *)out_buf;
  struct iphdr *ip_outer =
      (struct iphdr *)(out_buf + sizeof(struct ether_header));
  struct udphdr *udp_outer =
      (struct udphdr *)(out_buf + sizeof(struct ether_header) +
                        sizeof(struct iphdr));
  uint8_t *gtpu = out_buf + sizeof(struct ether_header) + sizeof(struct iphdr) +
                  sizeof(struct udphdr);
  uint8_t *payload = gtpu + GTPU_HDR_LEN;

  memcpy(payload, orig, actual_inner);

  gtpu[0] = 0x34;
  gtpu[1] = 0xFF;
  uint16_t gtpu_len = htons(actual_inner + 8);
  memcpy(&gtpu[2], &gtpu_len, 2);
  uint32_t teid_n = htonl(TEID);
  memcpy(&gtpu[4], &teid_n, 4);
  memset(&gtpu[8], 0x00, 3);
  gtpu[11] = 0x85;
  gtpu[12] = 0x01;
  gtpu[13] = (0x1 << 4);
  gtpu[14] = QFI & 0x3F;
  gtpu[15] = 0x00;

  int total_payload = GTPU_HDR_LEN + actual_inner;

  memcpy(eth->ether_shost, SRC_MAC, 6);
  memcpy(eth->ether_dhost, DST_MAC, 6);
  eth->ether_type = htons(ETHERTYPE_IP);

  ip_outer->ihl = 5;
  ip_outer->version = 4;
  ip_outer->tos = 0;
  ip_outer->tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct udphdr) + total_payload);
  ip_outer->id = htons(0);
  ip_outer->frag_off = 0;
  ip_outer->ttl = 64;
  ip_outer->protocol = IPPROTO_UDP;
  ip_outer->saddr = inet_addr(SRC_IP);
  ip_outer->daddr = inet_addr(DST_IP);
  ip_outer->check = 0;

  unsigned long sum = 0;
  unsigned short *ip_hdr = (unsigned short *)ip_outer;
  for (int i = 0; i < 10; i++)
    sum += ip_hdr[i];
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  ip_outer->check = (unsigned short)(~sum);

  udp_outer->source = htons(12345);
  udp_outer->dest = htons(GTPU_PORT);
  udp_outer->len = htons(sizeof(struct udphdr) + total_payload);
  udp_outer->check = 0;

  return sizeof(struct ether_header) + sizeof(struct iphdr) +
         sizeof(struct udphdr) + total_payload;
}

int main(int argc, char *argv[]) {
  if (argc < 5) {
    fprintf(stderr,
            "Usage: %s <input.pcap> <interface> --teid <hex> --qfi <int> "
            "[--qfi-file <path>]\n",
            argv[0]);
    return 1;
  }

  const char *pcap_file = argv[1];
  const char *interface = argv[2];

  for (int i = 3; i < argc; i++) {
    if (strcmp(argv[i], "--teid") == 0 && i + 1 < argc) {
      TEID = (uint32_t)strtoul(argv[++i], NULL, 16);
    } else if (strcmp(argv[i], "--qfi") == 0 && i + 1 < argc) {
      QFI = (uint8_t)atoi(argv[++i]);
    } else if (strcmp(argv[i], "--qfi-file") == 0 && i + 1 < argc) {
      QFI_FILE_PATH = argv[++i];
    }
  }

  if (!parse_mac(SRC_MAC_STR, SRC_MAC) || !parse_mac(DST_MAC_STR, DST_MAC)) {
    fprintf(stderr, "Invalid MAC address\n");
    return 1;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
    return 1;
  }

  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
    perror("SIOCGIFINDEX");
    close(sockfd);
    return 1;
  }
  int ifindex = ifr.ifr_ifindex;

  struct sockaddr_ll sa = {0};
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = ifindex;
  sa.sll_halen = ETH_ALEN;

  struct pcap_pkthdr *header;
  const u_char *packet;
  struct timeval first_ts = {0};
  struct timespec start_time;

  clock_gettime(CLOCK_MONOTONIC, &start_time);
  uint8_t out_buf[MAX_PKT_SIZE];

  while (pcap_next_ex(handle, &header, &packet) > 0) {
    if (first_ts.tv_sec == 0)
      first_ts = header->ts;

    struct timespec delay, target;
    timespec_diff(&header->ts, &first_ts, &delay);
    timespec_add(&start_time, &delay, &target);
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &target, NULL);

    check_qfi_update();

    int len = wrap_gtpu_packet(packet, header->caplen, out_buf);
    ssize_t sent =
        sendto(sockfd, out_buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    if (sent < 0)
      perror("sendto");
  }

  pcap_close(handle);
  close(sockfd);
  return 0;
}

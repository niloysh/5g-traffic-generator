/**
 * @file gtpu_replay.c
 * @brief Replays GTP-U encapsulated traffic from a PCAP file.
 *
 * @author Niloy Saha
 * @email niloysaha.ns@gmail.com
 *
 * @details Reads packets from a PCAP file containing GTP-U encapsulated
 * traffic and sends them out through a specified network interface,
 * attempting to preserve the original inter-packet timing.
 *
 * @usage sudo ./gtpu_replay <wrapped_gtpu.pcap> <interface>
 * @example sudo ./gtpu_replay wrapped_gtpu.pcap enp2s0f0
 */

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_PKT_SIZE 2048

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

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s wrapped_gtpu.pcap <interface>\n", argv[0]);
    return 1;
  }

  const char *pcap_file = argv[1];
  const char *interface = argv[2];

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

  while (pcap_next_ex(handle, &header, &packet) > 0) {
    if (first_ts.tv_sec == 0) {
      first_ts = header->ts;
      clock_gettime(CLOCK_MONOTONIC, &start_time);
    }

    struct timespec delay;
    timespec_diff(&header->ts, &first_ts, &delay);

    struct timespec target;
    timespec_add(&start_time, &delay, &target);

    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &target, NULL);

    ssize_t sent = sendto(sockfd, packet, header->caplen, 0,
                          (struct sockaddr *)&sa, sizeof(sa));
    if (sent < 0) {
      perror("sendto");
    }
  }

  pcap_close(handle);
  close(sockfd);
  return 0;
}

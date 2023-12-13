//
// Created by loumouli on 12/13/23.
//

#include "ft_malcolm.h"

void mac_str_to_hex(uint8_t* mac_addr, uint8_t* dest) {
  const int ret = sscanf((char *)mac_addr, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &dest[0], &dest[1], &dest[2],
                         &dest[3],
                         &dest[4], &dest[5]);
  if (ret != 6)
    error("mac_str_to_hex", "failed parsing mac address to byte array", __FILE__, __LINE__, __func__);
}

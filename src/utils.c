//
// Created by loumouli on 12/13/23.
//

#include "ft_malcolm.h"

void exit_syscall(void) {
  __asm__(
    "movq $60, %rax\n" // syscall number for exit
    "movq $1, %rdi\n" // exit status 1
    "syscall"
  );
}

void error(const char* func_error, const char* error_msg, const char* file, const int line, const char* func_caller) {
  dprintf(2, RED "ERROR: %s error: %s, caller: %s, file: %s, line: %d\n" RESET, func_error,
          error_msg ? error_msg : strerror(errno), func_caller, file, line);
  exit_syscall();
}

void mac_str_to_hex(uint8_t* mac_addr, uint8_t* dest) {
  const int ret = sscanf((char *)mac_addr, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &dest[0], &dest[1], &dest[2],
                         &dest[3], &dest[4], &dest[5]);
  if (ret != 6)
    error("mac_str_to_hex", "failed parsing mac address to byte array", __FILE__, __LINE__, __func__);
}

void print_ethernet_frame(const ethernet_frame* eth) {
  dprintf(1, "\t\tdest addr: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dest_addr[0], eth->dest_addr[1], eth->dest_addr[2],
          eth->dest_addr[3], eth->dest_addr[4], eth->dest_addr[5]);
  dprintf(1, "\t\tsrc addr: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->src_addr[0], eth->src_addr[1], eth->src_addr[2],
          eth->src_addr[3], eth->src_addr[4], eth->src_addr[5]);
  dprintf(1, "\t\tethertype: %02x:%02x\n", eth->ethertype[0], eth->ethertype[1]);
}

void print_arp_packet(const t_packet* packet) {
  dprintf(1, "\t\tar_hrd: %02x:%02x\n", packet->ar_hrd >> 8, packet->ar_hrd & 0xff);
  dprintf(1, "\t\tar_pro: %02x:%02x\n", packet->ar_pro >> 8, packet->ar_pro & 0xff);
  dprintf(1, "\t\tar_hln: %02x\n", packet->ar_hln);
  dprintf(1, "\t\tar_pln: %02x\n", packet->ar_pln);
  dprintf(1, "\t\tar_op: %02x:%02x\n", packet->ar_op >> 8, packet->ar_op & 0xff);
  dprintf(1, "\t\tar_sha: %02x:%02x:%02x:%02x:%02x:%02x\n", packet->ar_sha[0], packet->ar_sha[1], packet->ar_sha[2],
          packet->ar_sha[3], packet->ar_sha[4], packet->ar_sha[5]);
  dprintf(1, "\t\tar_sip: %02x:%02x:%02x:%02x || %s\n", packet->ar_sip[0], packet->ar_sip[1], packet->ar_sip[2],
          packet->ar_sip[3], inet_ntoa(*(struct in_addr *)packet->ar_sip));
  dprintf(1, "\t\tar_tha: %02x:%02x:%02x:%02x:%02x:%02x\n", packet->ar_tha[0], packet->ar_tha[1], packet->ar_tha[2],
          packet->ar_tha[3], packet->ar_tha[4], packet->ar_tha[5]);
  dprintf(1, "\t\tar_tip: %02x:%02x:%02x:%02x || %s\n", packet->ar_tip[0], packet->ar_tip[1], packet->ar_tip[2],
          packet->ar_tip[3], inet_ntoa(*(struct in_addr *)packet->ar_tip));
}

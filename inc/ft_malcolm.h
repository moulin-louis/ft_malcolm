//
// Created by loumouli on 12/13/23.
//

#ifndef FT_malcolm_H
#define FT_malcolm_H

#include <libft.h>

#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <ifaddrs.h>

extern char stop;

#define HW_TYPE_ETHERNET 0x0001 // 1
#define LEN_HW_ETHERNET 6
#define LEN_PROTO_IPV4 4
# define INTERFACE_NAME "eth0"

#pragma pack(1)
typedef struct {
  uint8_t* ip_src; //string representation of ip_source
  uint8_t ip_src_byte_arr[4]; //bytes representation of ip_source
  uint8_t* mac_src; //string repre of mac_source
  uint8_t mac_src_byte_arr[6]; //bytes repre of mac_source 
  uint8_t* ip_target; //string repre of ip_target
  uint8_t ip_target_byte_arr[4]; //bytes repre of ip_target
  uint8_t* mac_target; //string repre of mac_target
  uint8_t mac_target_byte_arr[6]; //bytes repre of mac_target
  int32_t sock; //socket used to respond back
  struct ifreq ifr;
  uint32_t index; //index of the interface used
  struct sockaddr_in* brd;
  uint8_t brd_addr[IF_NAMESIZE]; //broadcast address
  int32_t sock_broad; //socket used to listen to broadcast
} t_malcolm;
#pragma pack()

#pragma pack(1)
typedef struct {
  uint16_t ar_hrd; /* Format of hardware address.  */
  uint16_t ar_pro; /* Format of protocol address.  */
  uint8_t ar_hln; /* Length of hardware address.  */
  uint8_t ar_pln; /* Length of protocol address.  */
  uint16_t ar_op; /* ARP opcode (command).  */

  uint8_t ar_sha[ETH_ALEN]; /* Sender hardware address.  */
  uint8_t ar_sip[4]; /* Sender IP address.  */
  uint8_t ar_tha[ETH_ALEN]; /* Target hardware address.  */
  uint8_t ar_tip[4]; /* Target IP address.  */
} t_packet;
#pragma pack()

#pragma pack(1)
typedef struct {
  uint8_t dest_addr[ETHER_ADDR_LEN];
  uint8_t src_addr[ETHER_ADDR_LEN];
  uint8_t ethertype[ETHER_TYPE_LEN];
  uint8_t data[1024];
} ethernet_frame;
#pragma pack()

# define RED "\033[0;31m"
# define GREEN "\033[0;32m"
# define YELLOW "\033[0;33m"
# define RESET "\x1B[0m"

void mac_str_to_hex(uint8_t* mac_addr, uint8_t* dest);

void error(const char* func_error, const char* error_msg, const char* file, const int line, const char* func_caller);

void send_fake_arp_packet(const t_malcolm* malcolm, const uint32_t target);

void restore_arp_tables(const t_malcolm* malcolm, const uint32_t target);

void spoof_back_request(const t_malcolm* malcolm, const ethernet_frame* eth_frame);

void print_arp_packet(const t_packet* packet);

void print_ethernet_frame(const ethernet_frame* eth);
#endif //FT_malcolm_H

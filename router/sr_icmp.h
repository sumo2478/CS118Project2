/*-----------------------------------------------------------------------------
* File: sr_icmp.h
* Date: Winter 2014
* Authors: Alex Guo, Collin Yen, Andre Hsu
*
* Description:
*
*
*---------------------------------------------------------------------------*/

#ifndef sr_ICMP_H
#define sr_ICMP_H

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include <stdint.h>
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_ip.h"

#define ICMP_HEADER_LEN 8
#define IP_HEADER_LEN 20

void send_icmp_packet (struct sr_instance* sr,
                            uint32_t dest_ip,
                            uint32_t src_ip,
                            uint8_t * data,
                            unsigned int len,
                            uint8_t icmp_type,
                            uint8_t icmp_code,
                            uint8_t icmp_rest);

void handle_icmp (struct sr_instance* sr,
                            uint32_t src_ip_add,
                            uint32_t dest_ip_add,
                            uint8_t * packet,
                            unsigned int len, 
                            uint8_t icmp_type,
                            uint8_t icmp_code);

#endif
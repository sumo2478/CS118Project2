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

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include <stdint.h>
#include "sr_router.h"

#define ICMP_HEADER_LEN 8
#define IP_HEADER_LEN 20

void send_icmp_packet(struct sr_instance* sr, 
                      uint8_t* packet,
                      unsigned int len,
                      uint8_t icmp_type, 
                      uint8_t icmp_code,
                      char* interface
                      );

void handle_icmp (struct sr_instance* sr,
                  uint8_t* packet,
                  unsigned int len,
                  char* interface);


#endif

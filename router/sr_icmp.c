/*-----------------------------------------------------------------------------
 * File: sr_icmp.c
 * Date: Winter 2014
 * Authors: Alex Guo, Collin Yen, Andre Hsu
 *
 * Description:
 *
 *
 *---------------------------------------------------------------------------*/

/*

TODO: delete when done
FOR REFERENCE
Structure of a ICMP header
 
struct sr_icmp_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  
} __attribute__ ((packed)) ;
typedef struct sr_icmp_hdr sr_icmp_hdr_t;


Structure of a type3 ICMP header
 
struct sr_icmp_t3_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  uint16_t unused;
  uint16_t next_mtu;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t3_hdr sr_icmp_t3_hdr_t;

*/

#include <stdint.h>

#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_if.h"
#include "sr_ip.h"
#include "sr_icmp.h"
#include "sr_protocol.h"
#include "sr_rt.h"

void send_icmp_packet(struct sr_instance* sr, 
                      uint8_t* packet,
                      unsigned int len,
                      uint8_t icmp_type, 
                      uint8_t icmp_code,
                      char* interface
                      )
{
	struct sr_ethernet_hdr* ethernet_header = (struct sr_ethernet_hdr*) packet;
	struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*) (packet + sizeof(struct sr_ethernet_hdr));

	/* Form the ICMP Header */
	struct sr_icmp_t3_hdr* icmp_header = malloc(sizeof(struct sr_icmp_t3_hdr));
	icmp_header->icmp_type = icmp_type;
	icmp_header->icmp_code = icmp_code;
	icmp_header->unused = 0;
	icmp_header->next_mtu = 0;
	memcpy(icmp_header->data, ip_header, ICMP_DATA_SIZE);

	icmp_header->icmp_sum = 0;
	icmp_header->icmp_sum  = cksum(icmp_header, sizeof(struct sr_icmp_t3_hdr));

	/* Form the IP Reply Header*/
	struct sr_ip_hdr* ip_reply = malloc(sizeof(struct sr_ip_hdr));
	ip_reply->ip_v = 4;
    ip_reply->ip_hl = 5;
    ip_reply->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
    ip_reply->ip_tos = 0;
    ip_reply->ip_id = 0;
    ip_reply->ip_off = htons(IP_DF);
    ip_reply->ip_ttl = 64;
    ip_reply->ip_p = ip_protocol_icmp;
    ip_reply->ip_src = ip_header->ip_dst;
    ip_reply->ip_dst = ip_header->ip_src;

    ip_reply->ip_sum = 0;
    ip_reply->ip_sum = cksum(ip_reply, sizeof(struct sr_ip_hdr));

    /* Form the Ethernet Reply Header */
    struct sr_ethernet_hdr* ethernet_reply = malloc(sizeof(struct sr_ethernet_hdr));
    memcpy(ethernet_reply->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet_reply->ether_shost, ethernet_header->ether_dhost, ETHER_ADDR_LEN);
    ethernet_reply->ether_type = htons(ethertype_ip);

    unsigned int buffer_length = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
    uint8_t* buffer = (uint8_t*) malloc(buffer_length);

    memcpy(buffer, ethernet_reply, sizeof(struct sr_ethernet_hdr));
    memcpy(buffer + sizeof(struct sr_ethernet_hdr), ip_reply, sizeof(struct sr_ip_hdr));
    memcpy(buffer + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), icmp_header, sizeof(struct sr_icmp_t3_hdr));

    printf("Sending ICMP Reply: \n");
    print_hdrs(buffer, buffer_length);

    sr_send_packet(sr, buffer, buffer_length, interface);

	free(icmp_header);
	free(ip_reply);
	free(ethernet_reply);
	free(buffer);
}


/*
void handle_icmp (struct sr_instance* sr,
                            uint32_t src_ip_add,
                            uint32_t dest_ip_add,
                            uint8_t * packet,
                            unsigned int len, 
                            uint8_t icmp_type,
                            uint8_t icmp_code)
{
	printf("Handling ICMP packet \n");
	if(icmp_type == 0) {
		struct sr_icmp_hdr* icmp_header = (struct sr_icmp_hdr*) (packet + IP_HEADER_LEN);
		int echo_type = 8;
		if(icmp_header->icmp_type != echo_type)
			return;
		
		uint16_t original_checksum = icmp_header->icmp_sum;
		icmp_header->icmp_sum = 0;
		icmp_header->icmp_sum = cksum(icmp_header, len - IP_HEADER_LEN);
		if( original_checksum == icmp_header->icmp_sum)
		{
			send_icmp_packet(sr, dest_ip_add, src_ip_add, packet + ICMP_HEADER_LEN + IP_HEADER_LEN,len - ICMP_HEADER_LEN - IP_HEADER_LEN,0,0, icmp_header->icmp_rest);
		}
	}
	else {
		int len_to_send;
		if(len > IP_HEADER_LEN + 8)
			len_to_send = len;
		else
			len_to_send = IP_HEADER_LEN + 8;

		send_icmp_packet(sr, src_ip_add, dest_ip_add, packet, len_to_send, icmp_type, icmp_code, 0);
	}
}*/

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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_if.h"
#include "sr_ip.h"
#include "sr_icmp.h"
#include "sr_protocol.h"
#include "sr_rt.h"

/* Only use when if(ip_header->ip_p == ip_protocol_icmp) in HandleIP then this function will
	detect if it's an echo
*/
void handle_icmp_echo(struct sr_instance* sr, char * interface, uint8_t * packet, unsigned int len)
{
	/* first check validity of icmp packet */
	struct sr_if * receivedInterface = sr_get_interface(sr, interface);
	sr_icmp_hdr_t * icmp_header = (sr_icmp_hdr_t *) (packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	assert(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
	int cksum_icmp = icmp_header->icmp_sum;
	icmp_header->icmp_sum = 0;
	assert(cksum_icmp = cksum((void *) icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));
	
	/* then check if it was an echo SPECIAL CASE ICMP*/
	if (icmp_header->icmp_type == 8)
	{
		/*Handle Echo*/
		sr_ip_hdr_t * ip_header;
    	ip_header = (sr_ip_hdr_t *) (packet+sizeof(sr_ethernet_hdr_t));
    	int chksum = ip_header->ip_sum;
	    ip_header->ip_sum = 0;
	    assert(chksum == cksum(ip_header, sizeof(sr_ip_hdr_t)));

		icmp_header->icmp_type = 0;
		icmp_header->icmp_code = 0;
		icmp_header->icmp_sum = cksum((void *) icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

		sr_ethernet_hdr_t * ethernet_header;
		ethernet_header = (sr_ethernet_hdr_t *) packet;

		ip_header->ip_dst = ip_header->ip_src;
		ip_header->ip_src = receivedInterface->ip;
		ip_header->ip_sum = 0;
		ip_header->ip_sum = cksum((void *) ip_header, sizeof(sr_ip_hdr_t));

		memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
		memcpy(ethernet_header->ether_shost, receivedInterface->addr, ETHER_ADDR_LEN);
		sr_send_packet(sr, packet, len, receivedInterface->name);
	}
}

/*how to use: suppose we have:
if (ip_hdr->ip_ttl == 0)
      {
        sr_send_t3_icmp(11, 0, packet, sr, interface);
        return;
      } 
      */

/* call with appropriate code when the case comes up*/
void send_icmp_packet(struct sr_instance * sr, char * interface, uint8_t * packet, int type, int code)
{
  int packetLength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t * sendPacket = (uint8_t *) malloc(packetLength);
  memset(sendPacket, 0, packetLength);
  
  sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *) sendPacket;
  sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *) (sendPacket+sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t * icmp_header = (sr_icmp_t3_hdr_t *) (sendPacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
  
  struct sr_if * receivedInterface = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t * receivedEthernetHeader = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t * receivedIPheader = (sr_ip_hdr_t *) (packet+sizeof(sr_ethernet_hdr_t));

  /* Fill in ICMP Packet */
  icmp_header->icmp_type = type;
  icmp_header->icmp_code = code;
  memcpy(icmp_header->data, receivedIPheader, ICMP_DATA_SIZE);
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum =  cksum((void *) icmp_header, sizeof(sr_icmp_t3_hdr_t));
  
  /* Put the ICMP Packet in IP packet */
  ip_header->ip_hl = receivedIPheader->ip_hl;
  ip_header->ip_v = receivedIPheader->ip_v;
  ip_header->ip_tos = receivedIPheader->ip_tos;
  ip_header->ip_id = receivedIPheader->ip_id;
  ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_header->ip_off = receivedIPheader->ip_off;
  ip_header->ip_ttl = 64;
  ip_header->ip_p = ip_protocol_icmp;
  ip_header->ip_src = receivedInterface->ip;
  ip_header->ip_dst = receivedIPheader->ip_src;
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum((void *) ip_header, sizeof(sr_ip_hdr_t));

  /* Put IP packet in the Ethernet packet */
  memcpy(ethernet_header->ether_dhost, receivedEthernetHeader->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_shost, receivedInterface->addr, ETHER_ADDR_LEN);
  ethernet_header->ether_type = htons(ethertype_ip);

  sr_send_packet(sr, sendPacket, packetLength, receivedInterface->name);
}

/*
void send_icmp_packet (struct sr_instance* sr,
                            uint32_t dest_ip,
                            uint32_t src_ip,
                            uint8_t * data,
                            unsigned int len,
                            uint8_t icmp_type,
                            uint8_t icmp_code,
                            uint32_t icmp_rest)
{
	/* Make icmp_header */
	/*
	uint8_t* buffer = malloc(ICMP_HEADER_LEN + len);
	struct sr_icmp_header* icmp_header = (struct sr_icmp_hdr*) buffer;

	icmp_header ->icmp_type = icmp_type;
	icmp_header ->icmp_code = icmp_code;
	icmp_header ->icmp_rest = icmp_rest;

	icmp_header ->icmp_sum = 0;
	memcpy(buffer + ICMP_HEADER_LEN, data, len);

	icmp_header->icmp_sum = cksum(icmp_header, ICMP_HEADER_LEN + len);
	
	int through = 0;
	if(src_ip != 0)
		through = 1;


	struct sr_rt* routing_node = sr->routing_table;
	unsigned long max_mask = 0; 		   
	struct sr_rt* destination_node = NULL; 

	while(routing_node)
	{
		unsigned long current_mask = routing_node->mask.s_addr & dest_ip;
		if (current_mask > max_mask)
		{
			max_mask = current_mask;
			destination_node = routing_node;
		}

		routing_node = routing_node->next;
	}


	if(through == 0) {
		struct sr_if* routing_interface = sr_get_interface(sr, destination_node->interface); 
		if(routing_interface == NULL)
			return;
		dest_ip = routing_interface->ip;
	}

	/* Make IP header */
	/*
	uint8_t* ip_buffer = malloc(IP_HEADER_LEN + len);
	memset(ip_buffer, 0, IP_HEADER_LEN + len);
    struct sr_ip_hdr * ip_header = (struct sr_ip_hdr*) ip_buffer;
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_len = htons(IP_HEADER_LEN + len);
    ip_header->ip_ttl = 64;
    ip_header->ip_p = ip_protocol_icmp;
    ip_header->ip_src = src_ip;
    ip_header->ip_dst = dest_ip;
    
    memcpy( ip_buffer + IP_HEADER_LEN, buffer, len );
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, IP_HEADER_LEN);
    
	int status = handle_ip(sr, ip_buffer, IP_HEADER_LEN + len, NULL);
	if(!status) {
		perror("Error: sending packet \n");
	}

	free(ip_buffer);
	free(buffer);
}

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
}
*/
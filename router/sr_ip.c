#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_ip.h"

uint16_t calculate_checksum(struct sr_ip_hdr* ip_header)
{
	uint32_t check_sum = 0; /* Need to use 32 bits because we can have overflow */
	uint16_t* curr = (uint16_t*)ip_header;

	/* Header length represents the number of 4 byte words and so we want 
		the number of 2 byte words, which represent 16 bit number for the
		checksum calculations
	*/
	int i;
	for(i = 0; i < ip_header->ip_hl*2; i++)
	{
		check_sum += *curr;
		curr++;
	}

	/* Add overflow bits back to the checksum */
	if (check_sum >> 16)
	{
		check_sum = (check_sum & 0xffff) + (check_sum >> 16);
	}

	/* Perform one's complement */
	check_sum = ~check_sum;

	return (uint16_t) check_sum;
}



int handle_ip(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
	if (len < sizeof(struct sr_ip_hdr))
	{
		printf("Bad IP Packet\n");
		return -1;
	}

	/* TODO: Verify checksum is correct */

	struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*) (packet + sizeof(struct sr_ethernet_hdr));

	/* Determine the next ip destination */
	struct sr_rt* routing_node = sr->routing_table;
	unsigned long max_mask = 0; 		   /* The closest anded mask to the current packet */
	struct sr_rt* destination_node = NULL; /* The destination node that should be sent to given the routing table */

	while(routing_node)
	{
		/* If the masked address is the closest match then set it to the destination node */
		unsigned long current_mask = routing_node->mask.s_addr & ip_header->ip_dst;
		if (current_mask > max_mask)
		{
			max_mask = current_mask;
			destination_node = routing_node;
		}

		routing_node = routing_node->next;
	}

	struct sr_ip_hdr* ip_reply = (struct sr_ip_hdr*) malloc(sizeof(struct sr_ip_hdr));
	ip_reply->ip_hl  = ip_header->ip_hl;
	ip_reply->ip_v   = ip_header->ip_v;
	ip_reply->ip_tos = ip_header->ip_tos;
	ip_reply->ip_len = ip_header->ip_len;
	ip_reply->ip_id  = ip_header->ip_id;
	ip_reply->ip_off = ip_header->ip_off;
	ip_reply->ip_ttl = ip_header->ip_ttl--;
	ip_reply->ip_p   = ip_header->ip_p;
	ip_reply->ip_sum = 0;
	ip_reply->ip_src = ip_header->ip_src;
	ip_reply->ip_dst = ip_header->ip_dst;

	calculate_checksum(ip_reply);

	/* Determine the MAC address to send to */
	struct sr_ethernet_hdr* ethernet_reply = (struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
	struct sr_if* routing_interface = sr_get_interface(sr, destination_node->interface); 

	memcpy(ethernet_reply->ether_shost, routing_interface->addr, ETHER_ADDR_LEN);

	struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);
	int status = 0;
	/* ARP entry located in the queue */
	if (arp_entry)
	{
		/* Set the destination MAC address */
		memcpy(ethernet_reply->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

		 /* Place headers into packet buffer */
	    unsigned int buffer_length = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
	    uint8_t* buffer = (uint8_t*)malloc(buffer_length);
	    memcpy(buffer, ethernet_reply, sizeof(struct sr_ethernet_hdr));
	    memcpy(buffer + sizeof(struct sr_ethernet_hdr), ip_reply, sizeof(struct sr_ip_hdr));

	    status = sr_send_packet(sr, buffer, buffer_length, destination_node->interface);

		free(arp_entry);
	}
	/* Send new ARP request */
	else
	{	
		 /* Place headers into packet buffer */
	    unsigned int buffer_length = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
	    uint8_t* buffer = (uint8_t*)malloc(buffer_length);
	    memcpy(buffer, ethernet_reply, sizeof(struct sr_ethernet_hdr));
	    memcpy(buffer + sizeof(struct sr_ethernet_hdr), ip_reply, sizeof(struct sr_ip_hdr));

		struct sr_arpreq* arp_request = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, buffer, buffer_length, destination_node->interface);
		handle_arpreq(arp_request);
		return 0;
	}
	

	free(ip_reply);
	free(ethernet_reply);

    printf("Handling IP packet\n");
    return status;
}

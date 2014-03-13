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
	if (len < sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr))
	{
		printf("Bad IP Packet\n");
		/* TODO: Send ICMP Bad IP Packet error */
		return -1;
	}

	struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*) (packet + sizeof(struct sr_ethernet_hdr));

	/* TODO: Verify checksum is correct */
	uint16_t original_checksum = ip_header->ip_sum;
	ip_header->ip_sum = 0;
	if (original_checksum != calculate_checksum(ip_header))
	{
		printf("Checksum Error\n");
		/* TODO: Send ICMP checksum error */
		return -1;
	}

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

	/* Check to make sure the TTL hasn't run out 
	    Use 1 because we decrement to 0 */
	if (ip_header->ip_ttl == 1)
	{
		printf("TTL expired\n");
		/* TODO: Send ICMP checksum error */
		return -1;
	}

	/* Update values in ip header */
	ip_header->ip_ttl--;
	ip_header->ip_sum = 0;
	ip_header->ip_sum = calculate_checksum(ip_header);

	/* Determine the MAC address to send to */
	struct sr_ethernet_hdr* ethernet_reply = (struct sr_ethernet_hdr*) packet;
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
	    status = sr_send_packet(sr, packet, len, destination_node->interface);

		free(arp_entry);
	}
	/* Send new ARP request */
	else
	{	
		 /* Place headers into packet buffer */
		struct sr_arpreq* arp_request = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, destination_node->interface);
		handle_arpreq(arp_request);
		return 0;
	}

    printf("Handling IP packet\n");
    return status;
}

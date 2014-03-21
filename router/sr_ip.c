#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_ip.h"
#include "sr_utils.h"

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
	if (original_checksum != cksum(ip_header, sizeof(struct sr_ip_hdr)))
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
		uint32_t mask = routing_node->mask.s_addr & routing_node->dest.s_addr;
		uint32_t current_mask = mask & ip_header->ip_dst;
	
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
	ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));

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
		handle_arpreq(sr, arp_request);
		return 0;
	}

    return status;
}

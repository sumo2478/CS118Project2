#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_ip.h"
#include "sr_utils.h"
#include "sr_icmp.h"

int handle_ip(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
	if (len < sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr))
	{
		printf("Bad IP Packet\n");
		return -1;
	}

	struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*) (packet + sizeof(struct sr_ethernet_hdr));

	/* Verify Checksum */
	uint16_t original_checksum = ip_header->ip_sum;
	ip_header->ip_sum = 0;
	if (original_checksum != cksum(ip_header, sizeof(struct sr_ip_hdr)))
	{
		printf("Checksum Error\n");
		return -1;
	}

	/* If the destination was pointed to the router interface then handle it based on the protocol */

	int dest_source = 0;
	struct sr_if* eth1 = sr_get_interface(sr, "eth1");
	struct sr_if* eth2 = sr_get_interface(sr, "eth2");
	struct sr_if* eth3 = sr_get_interface(sr, "eth3");

	
	if (eth1->ip == ip_header->ip_dst)
		dest_source = 1;
	else if (eth2->ip == ip_header->ip_dst)
		dest_source = 1;
	else if (eth3->ip == ip_header->ip_dst)
		dest_source = 1;

	if (dest_source)
	{
		if (ip_header->ip_p == ip_protocol_icmp)
		{
			printf("Handle ICMP\n");
			/* handle_icmp should only take in instance, buffer, length, and interface */
			handle_icmp(sr, packet, len, interface);
		}else
		{
			/* Send back Destination host unreachable */
			send_icmp_packet(sr, packet, len, 3, 3, interface);
			printf("Port Unreachable\n");
		}

		return 0;
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
		send_icmp_packet(sr, packet, len, 11, 0, interface);
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

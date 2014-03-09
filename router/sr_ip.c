#include <stdio.h>
#include <stdlib.h>

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"

int handle_ip(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
	if (len < sizeof(struct sr_ip_hdr))
	{
		printf("Bad IP Packet\n");
		return -1;
	}
	
	struct sr_ethernet_hdr* eth_header = (struct sr_ethernet_hdr*) packet;

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




    printf("Handling IP packet\n");
    return 0;
}

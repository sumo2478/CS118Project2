#include <stdio.h>
#include <stdlib.h>

#include "sr_protocol.h"
#include "sr_router.h"

int handle_ip(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
	if (len < sizeof(struct sr_ip_hdr))
	{
		printf("Bad IP Packet\n");
		return -1;
	}
	
	struct sr_ethernet_hdr* eth_header = (struct sr_ethernet_hdr*) packet;

	struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*) (packet + sizeof(struct sr_ethernet_hdr));

	struct sr_rt* routing_node = sr->routing_table;


    printf("Handling IP packet\n");
}

/*-----------------------------------------------------------------------------
 * File: sr_icmp.c
 * Date: Winter 2014
 * Authors: Alex Guo, Collin Yen, Andre Hsu
 *
 * Description:
 *
 *
 *---------------------------------------------------------------------------*/

#include "sr_icmp.h"

// TODO: delete when done
/*
// FOR REFERENCE
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

void send_icmp_packet (struct sr_instance* sr,
                            uint32_t dest_ip,
                            uint32_t src_ip,
                            uint8_t * data,
                            unsigned int len,
                            uint8_t icmp_type,
                            uint8_t icmp_code,
                            uint32_t icmp_rest)
{
	printf("Sending ICMP packet \n");

	// Create ICMP_header size of 8 bytes
	uint8_t* buffer = malloc(ICMP_HEADER_LEN + len);
	struct sr_icmp_hdr* icmp_header = (struct sr_icmp_hdr*) buffer;

	icmp_header ->icmp_type = icmp_type; // 4 bytes
	icmp_header ->icmp_code = icmp_code; // 4 bytes
	icmp_header ->icmp_rest = icmp_rest; // 32 bytes rest of header

	icmp_header ->icmp_sum = 0;
	memcpy(buffer + ICMP_HEADER_LEN, data, len);

	icmp_header->icmp_sum = cksum(icmp_header, ICMP_HEADER_LEN + len);
	
	int through = 0;
	if(src_ip != 0)
		through = 1;


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

	if(through == 0) {
		struct sr_if* routing_interface = sr_get_interface(sr, destination_node->interface); 
		if(routing_interface == NULL)
			return;
		dest_ip = routing_interface->ip;
	}


	// Create an IP frame
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
    ip_header0>ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, IP_HEADER_LEN);
    
    // TODO: Collin: how do I change use the interface paramter
    // @param: interface? how do I use
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
	/*
		icmp_type:
		Echo reply
		Destination net unreachable (type 3, code 0)
		Destination host unreachable (type 3, code 1)
		Port unreachable (type 3, code 3) 
		Time exceeded (type 11, code 0) 
	*/
	// Echo reply
	if(icmp_type == 0) {
		struct sr_icmp_hdr* icmp_header = (struct sr_icmp_hdr*) (packet + IP_HEADER_LEN);
		int echo_type = 8;
		if(icmp_header->icmp_type != echo type)
			return;
		
		uint16_t original_checksum = icmp_header->icmp_sum;
		icmp_header->icmp_sum = 0;
		icmp_header->icmp_sum = cksum(icmp_header, len - IP_HEADER_LEN)
		if( original_checksum == icmp_header->icmp_sum)
		{
			send_icmp_packet(sr, dest_ip_add, src_ip_add, packet + ICMP_HEADER_LEN + IP_HEADER_LEN,len - ICMP_HEADER_LEN - IP_HEADER_LEN,0,0, icmp_header->icmp_rest)
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
}
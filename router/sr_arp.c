#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_if.h"


/**
 * Handles an ARP Frame
 * Request -- Responds to the ARP request
 * Reply   -- Receives an ARP reply
 * @param  sr        -- the sr_instance of the router
 * @param  packet    -- the packet that was received
 * @param  len       -- the length of the packet
 * @param  interface -- the receiving interface
 * @return status code 0 for success, -1 for error
 */
int handle_arp(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
    struct sr_ethernet_hdr* eth_header = (struct sr_ethernet_hdr*) packet;
    
    struct sr_arp_hdr* arp_header = (struct sr_arp_hdr*)(packet + sizeof(sr_ethernet_hdr_t));

    /* Determine type of arp frame */
    if (ntohs(arp_header->ar_op) == arp_op_request)
    {
        printf("Handling ARP Request\n");
    	/* Obtain the correct interface */
    	struct sr_if* inter = sr_get_interface(sr, interface);

    	/* Construct the reply */
    	struct sr_arp_hdr* arp_reply = (struct sr_arp_hdr*)malloc(sizeof(struct sr_arp_hdr));

    	/* Initialize values for arp reply */
    	arp_reply->ar_hrd = arp_header->ar_hrd;
    	arp_reply->ar_pro = arp_header->ar_pro;
    	arp_reply->ar_hln = ETHER_ADDR_LEN; /* TODO: Might not be correct */
    	arp_reply->ar_pln = arp_header->ar_pln;
    	arp_reply->ar_op  = htons(arp_op_reply);
    	memcpy(arp_reply->ar_sha, inter->addr, ETHER_ADDR_LEN);
    	arp_reply->ar_sip = arp_header->ar_tip;
    	memcpy(arp_reply->ar_tha, arp_header->ar_tha, ETHER_ADDR_LEN);
    	arp_reply->ar_tip = arp_header->ar_sip;

    	/* Add Ethernet Header */
    	struct sr_ethernet_hdr* ethernet_reply = (struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
        memcpy(ethernet_reply->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernet_reply->ether_shost, inter->addr, ETHER_ADDR_LEN);
        ethernet_reply->ether_type = htons(ethertype_arp);

        /* Place headers into packet buffer */
        unsigned int buffer_length = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
        uint8_t* buffer = (uint8_t*)malloc(buffer_length);
        memcpy(buffer, ethernet_reply, sizeof(struct sr_ethernet_hdr));
        memcpy(buffer + sizeof(struct sr_ethernet_hdr), arp_reply, sizeof(struct sr_arp_hdr));

        /* Send the packet */
        int status = sr_send_packet(sr, buffer, buffer_length, interface);

        free(buffer);
        free(ethernet_reply);
        free(arp_reply);

        return status;

    }else if(ntohs(arp_header->ar_op) == arp_op_reply)
    {
    	printf("Handling ARP Reply\n");

        /* Insert the MAC to IP mapping into the cache */
        struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, eth_header->ether_shost, arp_header->ar_sip);

        if (req)
        {
            /* Handle all the packets associated with this request */
            struct sr_packet* current_packet = req->packets;

            while(current_packet)
            {
                printf("Sending packet\n");
                /* Add in the destination MAC address for the packet */
                struct sr_ethernet_hdr* ethernet_packet = (struct sr_ethernet_hdr*) current_packet->buf;
                memcpy(ethernet_packet->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);

                sr_send_packet(sr, current_packet->buf, current_packet->len, current_packet->iface);
                current_packet = current_packet->next;
            }


            sr_arpreq_destroy(&sr->cache, req);
        }
    }else
    {
    	return -1;
    }

    return 0;
}

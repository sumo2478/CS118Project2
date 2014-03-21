#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
  
    printf("Inside of sweepreqs\n");
    struct sr_arpreq *itr= sr->cache.requests;
    while(itr != NULL)
    {
        struct sr_arpreq* next= itr->next;
        handle_arpreq(sr, itr);
        itr= next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req)

{
    
    time_t now;
    
    time ( &now );
    
    if(difftime(now, req->sent) > 1.0)
        
    {
        
        if(req->times_sent >= 5)
            
        {
            
            /* Send icmp host unreachable to source addr of all pkts waiting on this request */
            printf("Destroying request\n");
            sr_arpreq_destroy(&sr->cache, req);
            
        }
        
        else
            
        {
            
            /* Broadcast arp request */
            
            printf("Inside of handle arprequest\n");
            
            /*Construct an interface holders*/
            printf("constructing interface holders\n");
            
            struct sr_if* eth1;
            
            struct sr_if* eth2;
            
            struct sr_if* eth3;
            
            eth1= sr_get_interface(sr, "eth1");
            
            eth2= sr_get_interface(sr, "eth2");
            
            eth3= sr_get_interface(sr, "eth3");
            
            struct sr_if* arr[3];
            
            arr[0]= eth1;
            
            arr[1]= eth2;
            
            arr[2]= eth3;
            
            printf("finished constructing interface holders\n");
            
            
        
            int i=0;
            
            for(i;i<3;i++)
                
            {
                printf("constructing and sending ARP request\n");
                /* APR HEADERS
                 
                 unsigned short  ar_hrd;                 format of hardware address
                 
                 unsigned short  ar_pro;                 format of protocol address
                 
                 unsigned char   ar_hln;                 length of hardware address
                 
                 unsigned char   ar_pln;                 length of protocol address
                 
                 unsigned short  ar_op;                  ARP opcode (command)
                 
                 unsigned char   ar_sha[ETHER_ADDR_LEN]; sender hardware address
                 
                 uint32_t        ar_sip;                 sender IP address
                 
                 unsigned char   ar_tha[ETHER_ADDR_LEN]; target hardware address
                 
                 uint32_t        ar_tip;                 target IP address
                 
                 */
                
                
                
                /* Construct the request */
                
                struct sr_arp_hdr* arp_request = (struct sr_arp_hdr*)malloc(sizeof(struct sr_arp_hdr));
                
                
                
                /* Initialize values for arp request */
                
                uint8_t tempTarget[ETHER_ADDR_LEN];
                int z=0;
                
                for(z;z<6;z++)
                    
                {
                    
                    tempTarget[z]= 0x00;
                    
                }
                
                arp_request->ar_hrd = htons(arp_hrd_ethernet);
                
                arp_request->ar_pro = htons(ethertype_ip);
                
                arp_request->ar_hln = ETHER_ADDR_LEN;
                
                arp_request->ar_pln = 0x0004;
                
                arp_request->ar_op  = htons(arp_op_request);
                
                memcpy(arp_request->ar_sha, arr[i]->addr, ETHER_ADDR_LEN);
                
                arp_request->ar_sip = arr[i]->ip;
                
                memcpy(arp_request->ar_tha, tempTarget, ETHER_ADDR_LEN);
                
                arp_request->ar_tip = req->ip;
                
                /* Add Ethernet Header */
                
                struct sr_ethernet_hdr* ethernet_request = (struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
                
                uint8_t tempMac[ETHER_ADDR_LEN];
                
                int j=0;
                
                for(j;j<6;j++)
                    
                {
                    
                    tempMac[j]= 0xFF;
                    
                }
                
                memcpy(ethernet_request->ether_dhost, tempMac, ETHER_ADDR_LEN);
                
                memcpy(ethernet_request->ether_shost, arr[i]->addr, ETHER_ADDR_LEN);
                
                ethernet_request->ether_type = htons(ethertype_arp);
                
                
                
                /* Place headers into packet buffer */
                
                unsigned int buffer_length = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
                
                uint8_t* buffer = (uint8_t*)malloc(buffer_length);
                
                memcpy(buffer, ethernet_request, sizeof(struct sr_ethernet_hdr));
                
                memcpy(buffer + sizeof(struct sr_ethernet_hdr), arp_request, sizeof(struct sr_arp_hdr));
                
                printf("printing buffer about to get sent out ");
                print_hdrs(buffer, buffer_length);
                printf("\n");
                /* Send the packet */
                printf("Sending out ARP request\n");
                int status = sr_send_packet(sr, buffer, buffer_length, arr[i]->name);
                printf("Finished sending ARP request\n");
                
                
                free(buffer);
                
                free(ethernet_request);
                
                free(arp_request);
                
            } /* end of broadcast arp request */
            
            
            req->sent = now;
            
            req->times_sent++;
            
        }
        
        
        
    }
    
}




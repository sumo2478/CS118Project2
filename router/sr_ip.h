

uint16_t calculate_checksum(struct sr_ip_hdr* ip_header);

int handle_ip(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);

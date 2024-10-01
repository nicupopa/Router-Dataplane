#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

#define MAX_RTABLE 100000
#define MAX_ARP 256
#define ETHERTYPE_IP 0x0800
#define ICMP_PROTOCOL 1
#define ICMP_CODE 0 // only code that interests us
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP_TIME_EXCEEDED 11
#define ICMP_DESTINATION_UNREACHABLE 3
#define ETHERTYPE_ARP 0x0806
#define TTL 64
#define ICMP_DATA sizeof(struct iphdr) + 8


// routing and arp table declarations
struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
    // binary search for best route
    // better than linear search :)
    struct route_table_entry *best_route = NULL;
    uint32_t left = 0;
    uint32_t right = rtable_len - 1;

    while (left <= right) {
        uint32_t mid = left + (right - left) / 2;

        if ((ip_dest & rtable[mid].mask) == (rtable[mid].prefix & rtable[mid].mask)) {
            // match found = best route
            if (left == right) {
                return &rtable[mid];
            } else {
                // rtable is sorted in descending order -> best_match is on the left
                left = 0;
                right = mid;
            }
        } else if ((ip_dest & rtable[mid].mask) < (rtable[mid].prefix & rtable[mid].mask)) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return best_route;
}

struct arp_table_entry *get_mac_entry(uint32_t ip_dest) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == ip_dest)
            return &arp_table[i];
    }
    return NULL;
}

void send_icmp_error(char* buf, uint8_t icmp_type, int interface) {
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    // make ip header
    size_t total_ip_length = sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_DATA;
    ip_hdr->tot_len = htons(total_ip_length);
    ip_hdr->protocol = ICMP_PROTOCOL;
    ip_hdr->ttl = TTL;
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = inet_addr(get_interface_ip(interface));

    // calculate ip checksum
    ip_hdr->check = 0;
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

    // create icmp header
    memset(icmp_hdr, 0, sizeof(struct icmphdr));
    icmp_hdr->type = icmp_type;
    icmp_hdr->code = ICMP_CODE;

    // copy ip header
    memcpy(icmp_hdr + sizeof(struct icmphdr), ip_hdr, ICMP_DATA);

    // icmp checksum
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + ICMP_DATA);

    // modify ether header
    struct ether_header new_ether;
    memcpy(new_ether.ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
    memcpy(new_ether.ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
    new_ether.ether_type = htons(ETHERTYPE_IP);

    // copy the headers to the buffer
    memcpy(buf, &new_ether, sizeof(struct ether_header));
    memcpy(buf + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
    memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr) + ICMP_DATA);

    // total length of the packet
    size_t len = sizeof(struct ether_header) + total_ip_length;

    // send packet
    send_to_link(interface, buf, len);
}

void send_icmp_reply(int interface, char *buf, size_t len)
{
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	uint32_t temp;
    // swap addresses
    temp = ip_hdr->saddr;
    ip_hdr->saddr = ip_hdr->daddr;
    ip_hdr->daddr = temp;

    // set type/code/calculate checksum
	icmp_hdr->type = ICMP_ECHO_REPLY;
	icmp_hdr->code = ICMP_CODE;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum((void *)icmp_hdr, sizeof(struct icmphdr));

    // send icmp reply
	send_to_link(interface, buf, len);
}

int comparator(const void* first, const void* second) {
    // compare in descending order
    const struct route_table_entry *first_cmp = (const struct route_table_entry *) first;
    const struct route_table_entry *second_cmp = (const struct route_table_entry *) second;

    // compare masks
    int mask_compare = (int)(second_cmp->mask - first_cmp->mask);
    if (mask_compare != 0) {
        return mask_compare;
    }

    // if masks are equal, compare prefixes
    return (int)(second_cmp->prefix - first_cmp->prefix);
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// rtable and arp_table allocations
	rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE);
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP);
	DIE(arp_table == NULL, "memory");
	
	// populate route/arp tables
	rtable_len = read_rtable(argv[1], rtable);
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), comparator);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

        // define headers
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
        struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

            // get router ip
            char* router_ip = get_interface_ip(interface);
            uint32_t router_ip_uint = inet_addr(router_ip);

            // verify if router is dest
            if (ip_hdr->daddr == router_ip_uint && ip_hdr->protocol == ICMP_PROTOCOL) {
                if (icmp_hdr->type == ICMP_ECHO_REQUEST) {
                    if (ip_hdr->ttl <= 1) {
                        send_icmp_error(buf, ICMP_TIME_EXCEEDED, interface);
                    } else {
                        // if packet is for the router
                        // send echo reply
                        send_icmp_reply(interface, buf, len);
                        continue;
                    }
                }
            } else {
                // calculate checksum, verify integrity
                uint16_t new_check = checksum((void*)ip_hdr, sizeof(struct iphdr));
                if (new_check != 0)
                    continue;

                // check ttl
                if (ip_hdr->ttl <= 1) {
                    send_icmp_error(buf, ICMP_TIME_EXCEEDED, interface);
                    continue;
                } else {
                    ip_hdr->ttl--;
                }

                // calculate best route
                struct route_table_entry* best_route = get_best_route(ip_hdr->daddr);
                 if (best_route == NULL) {
                    send_icmp_error(buf, ICMP_DESTINATION_UNREACHABLE, interface);
                    continue;
                }

                // recalculate checksum
                ip_hdr->check = ~(~ip_hdr->check + ~(ip_hdr->ttl + 1) + ip_hdr->ttl) - 1;

                struct arp_table_entry *entry = get_mac_entry(best_route->next_hop);

                if (entry == NULL) {
                    continue;
                } else {
                    // update mac address of next hop
                    memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(eth_hdr->ether_dhost));
                    get_interface_mac(best_route->interface, eth_hdr->ether_shost);

                    // send packet to next hop via interface
                    send_to_link(best_route->interface, buf, len);
                }
            }
        }
    }
}
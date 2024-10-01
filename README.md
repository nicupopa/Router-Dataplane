# README

## Overview

This program implements basic network packet handling, routing, and ARP functionalities for a router. It processes Ethernet frames, determines the best routes for packets using a routing table, and handles ARP requests to resolve MAC addresses. Additionally, the program responds to ICMP Echo requests and sends ICMP error messages when necessary.

### Key Features:
- **Routing Table Lookup**: The program uses a binary search to find the best route for each packet.
- **ARP Table Lookup**: MAC address resolution is done using an ARP table.
- **ICMP Error Handling**: It sends ICMP error responses for Time Exceeded and Destination Unreachable errors.
- **ICMP Echo Reply**: Responds to ICMP Echo requests (ping).
- **Packet Forwarding**: Forwards packets to the correct next hop based on the routing table.
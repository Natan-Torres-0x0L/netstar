#include "netstar-capture.h"

#include <collections/list/list.h>

#include <netstar-forward.h>

#include <netstar-threads.h>

#include <stdlib.h>
#include <string.h>


#define NETSTAR_CAPTURE_BUFFER_LENGTH 0xFFFF+1


static bool netstar_capture_started;


struct netstar_capture_forward {
  struct netstar_capture_packet *packet;
  netstar_t *netstar;
};


// typedef list_t * netstar_capture_packets_t;


// static netstar_capture_packets_t netstar_capture_packets;


/*
static inline void
netstar_capture_packets_add(struct netstar_capture_packet *packet) {
  list_pushfront(netstar_capture_packets, list_lvalue(packet, sizeof(struct netstar_capture_packet *)));
}

static inline netstar_capture_packets_t
netstar_capture_packets_new(void) {
  return list_new(free);
}

static inline void
netstar_capture_packets_free(void) {
  list_free(netstar_capture_packets);
}
*/


static void netstar_capture_packet_free(struct netstar_capture_packet *);


#define NETSTAR_CAPTURE_ETHERNET_VLAN_TPID_1 0x8100
#define NETSTAR_CAPTURE_ETHERNET_VLAN_TPID_2 0x88A8

static inline void
netstar_capture_packet_build_ethernet(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  struct netstar_ethernethdr *etherneth = (struct netstar_ethernethdr *)packet->ptr;
  size_t offset = 0;

  packet->layer |= NETSTAR_FORWARD_LAYER2;

  memcpy(&packet->layer2.smac, etherneth->shardware, NETWORK_MACADDR_SIZE);
  memcpy(&packet->layer2.dmac, etherneth->dhardware, NETWORK_MACADDR_SIZE);

  packet->layer2.protocol = ntohs(etherneth->type);

  while (packet->layer2.protocol == NETSTAR_CAPTURE_ETHERNET_VLAN_TPID_1 || packet->layer2.protocol == NETSTAR_CAPTURE_ETHERNET_VLAN_TPID_2) {
    if (length < (14+(offset += 4)+2))
      return;

    packet->layer2.protocol = ((packet->ptr[12+offset] << 8) | (packet->ptr[13+offset]));
  }

  packet->layer2.payload        = (uint8_t *)etherneth+NETSTAR_ETHERNET_SIZE+offset;
  packet->layer2.payload_length = length-(NETSTAR_ETHERNET_SIZE+offset);
  packet->layer2.ptr            = (void *)etherneth;
}

static void
netstar_capture_packet_build_arp(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  struct netstar_arphdr *arph = (struct netstar_arphdr *)(packet->layer2.payload);

  if (packet->layer2.payload_length < NETSTAR_ARP_SIZE)
    return;

  switch (ntohs(arph->opcode)) {
    case NETSTAR_ARP_OPCODE_REQUEST:
      packet->type |= NETSTAR_FORWARD_ARP_REQUEST;
      break;

    case NETSTAR_ARP_OPCODE_REPLY:
      packet->type |= NETSTAR_FORWARD_ARP_REPLY;
      break;
  }
  packet->layer |= NETSTAR_FORWARD_LAYER3;

  memcpy(&packet->layer3.saddr, &arph->saddr, NETWORK_IPADDR4_SIZE);
  memcpy(&packet->layer3.daddr, &arph->daddr, NETWORK_IPADDR4_SIZE);

  packet->layer3.ptr = (void *)arph;
}

static void
netstar_capture_packet_build_ipv4(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  struct netstar_iphdr *iph = (struct netstar_iphdr *)(packet->layer2.payload);

  if (packet->layer2.payload_length < NETSTAR_IP_SIZE)
    return;

  packet->type  |= NETSTAR_FORWARD_IPV4;
  packet->layer |= NETSTAR_FORWARD_LAYER3;

  memcpy(&packet->layer3.saddr, &iph->saddr, NETWORK_IPADDR4_SIZE);
  memcpy(&packet->layer3.daddr, &iph->daddr, NETWORK_IPADDR4_SIZE);
  packet->layer3.protocol       = iph->protocol;
  packet->layer3.payload        = (void *)((uint8_t *)packet->layer2.payload+NETSTAR_IP_SIZE);
  packet->layer3.payload_length = (size_t)((!iph->length) ? 0 : ntohs(iph->length)-(iph->ihl*4));
  packet->layer3.length         = ntohs(iph->length);
  packet->layer3.ptr            = (void *)((uint8_t *)packet->layer2.payload);
}

static void
netstar_capture_packet_build_ipv6(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  struct netstar_ipv6hdr *ipv6h = (struct netstar_ipv6hdr *)(packet->layer2.payload);

  if (packet->layer2.payload_length < NETSTAR_IPV6_SIZE)
    return;

  packet->type  |= NETSTAR_FORWARD_IPV6;
  packet->layer |= NETSTAR_FORWARD_LAYER3;

  memcpy(&packet->layer3.saddr, &ipv6h->saddr, NETWORK_IPADDR6_SIZE);
  memcpy(&packet->layer3.daddr, &ipv6h->daddr, NETWORK_IPADDR6_SIZE);
  packet->layer3.protocol       = ipv6h->nexthdr;
  packet->layer3.payload        = (void *)((uint8_t *)packet->layer2.payload+NETSTAR_IPV6_SIZE);
  packet->layer3.payload_length = (size_t)((!ipv6h->length) ? 0 : (size_t)(ntohs(ipv6h->length)));
  packet->layer3.length         = ntohs(ipv6h->length);
  packet->layer3.ptr            = (void *)((uint8_t *)packet->layer2.payload);
}

static void
netstar_capture_packet_build_icmpv4(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  if (packet->layer3.payload_length < NETSTAR_ICMP_SIZE)
    return;

  packet->type |= NETSTAR_FORWARD_ICMPV4;
}

static void
netstar_capture_packet_build_icmpv6(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  struct netstar_icmpv6hdr *icmp6h = (struct netstar_icmpv6hdr *)(packet->layer3.payload);

  if (packet->layer3.payload_length < NETSTAR_ICMPV6_SIZE)
    return;

  packet->type |= NETSTAR_FORWARD_ICMPV6;

  switch (icmp6h->type) {
    case NETSTAR_NDP_TYPE_NEIGHBOR_SOLICIT:
    case NETSTAR_NDP_TYPE_ROUTER_SOLICIT:
      packet->type |= NETSTAR_FORWARD_NDP_SOLICIT;
      break;

    case NETSTAR_NDP_TYPE_NEIGHBOR_ADVERT:
    case NETSTAR_NDP_TYPE_ROUTER_ADVERT:
      packet->type |= NETSTAR_FORWARD_NDP_ADVERT;
      break;
  }
}

static void
netstar_capture_packet_build_tcp(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  struct netstar_tcphdr *tcph = (struct netstar_tcphdr *)(packet->layer3.payload);

  if (packet->layer3.payload_length < NETSTAR_TCP_SIZE)
    return;

  if (packet->layer2.protocol == NETSTAR_ETHERNET_PROTOCOL_IPV4)
    packet->type |= NETSTAR_FORWARD_TCPV4;
  else if (packet->layer2.protocol == NETSTAR_ETHERNET_PROTOCOL_IPV6)
    packet->type |= NETSTAR_FORWARD_TCPV6;

  packet->layer |= NETSTAR_FORWARD_LAYER4;

  if ((packet->layer4.protocol = network_iana_protocolbyport(ntohs(tcph->sport))) == NETWORK_IANA_UNKNOWN_PROTOCOL)
    packet->layer4.protocol = network_iana_protocolbyport(ntohs(tcph->dport));

  packet->layer4.sport          = ntohs(tcph->sport);
  packet->layer4.dport          = ntohs(tcph->dport);
  packet->layer4.sequence       = ntohl(tcph->sequence);
  packet->layer4.acknowledgment = ntohl(tcph->acknowledgment);
  packet->layer4.payload        = (void *)((uint8_t *)tcph + /* NETSTAR_TCP_SIZE */ (tcph->data_offset*4));
  packet->layer4.payload_length = packet->layer3.payload_length - /* NETSTAR_TCP_SIZE */ (tcph->data_offset*4);
  packet->layer4.length         = packet->layer3.payload_length;
  packet->layer4.ptr            = (void *)tcph;
}

static void
netstar_capture_packet_build_udp(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  struct netstar_udphdr *udph = (struct netstar_udphdr *)(packet->layer3.payload);

  if (packet->layer3.payload_length < NETSTAR_UDP_SIZE)
    return;

  if (packet->layer2.protocol == NETSTAR_ETHERNET_PROTOCOL_IPV4)
    packet->type |= NETSTAR_FORWARD_UDPV4;
  else if (packet->layer2.protocol == NETSTAR_ETHERNET_PROTOCOL_IPV6)
    packet->type |= NETSTAR_FORWARD_UDPV6;

  packet->layer |= NETSTAR_FORWARD_LAYER4;

  if ((packet->layer4.protocol = network_iana_protocolbyport(ntohs(udph->sport))) == NETWORK_IANA_UNKNOWN_PROTOCOL)
    packet->layer4.protocol = network_iana_protocolbyport(ntohs(udph->dport));

  packet->layer4.sport          = ntohs(udph->sport);
  packet->layer4.dport          = ntohs(udph->dport);
  packet->layer4.payload        = (void *)((uint8_t *)udph+NETSTAR_UDP_SIZE);
  packet->layer4.payload_length = packet->layer3.payload_length-NETSTAR_UDP_SIZE;
  packet->layer4.length         = ntohs(udph->length);
  packet->layer4.ptr            = (void *)udph;
}

static void
netstar_capture_packet_build(struct netstar_capture_packet *packet, uint8_t *buffer, size_t length) {
  netstar_capture_packet_build_ethernet(packet, buffer, length);

  switch (packet->layer2.protocol) {
    case NETSTAR_ETHERNET_PROTOCOL_ARP:
      netstar_capture_packet_build_arp(packet, buffer, length);
      break;

    case NETSTAR_ETHERNET_PROTOCOL_IPV4:
      netstar_capture_packet_build_ipv4(packet, buffer, length);
      break;

    case NETSTAR_ETHERNET_PROTOCOL_IPV6:
      netstar_capture_packet_build_ipv6(packet, buffer, length);
      break;
  }

  switch (packet->layer3.protocol) {
    case NETSTAR_IP_PROTOCOL_ICMPV4:
      netstar_capture_packet_build_icmpv4(packet, buffer, length);
      break;

    case NETSTAR_IP_PROTOCOL_ICMPV6:
      netstar_capture_packet_build_icmpv6(packet, buffer, length);
      break;

    case NETSTAR_IP_PROTOCOL_TCP:
      netstar_capture_packet_build_tcp(packet, buffer, length);
      break;

    case NETSTAR_IP_PROTOCOL_UDP:
      netstar_capture_packet_build_udp(packet, buffer, length);
      break;
  }
}

#ifdef NETSTAR_CAPTURE_PACKET_FORWARD_MULTITHREAD_ROUTINE
static void
netstar_capture_packet_forward(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;
  struct netstar_capture_forward *forward = (struct netstar_capture_forward *)thread->args;

  netstar_forward(forward->netstar, forward->packet);
}
#endif

static struct netstar_capture_packet *
netstar_capture_packet_new(uint8_t *buffer, size_t length) {
  struct netstar_capture_packet *packet = NULL;

  if (!(packet = (struct netstar_capture_packet *)calloc(1, sizeof(struct netstar_capture_packet))))
    goto _return;

  if (!(packet->ptr = (uint8_t *)calloc(length, sizeof(uint8_t))))
    goto _return;

  memcpy(packet->ptr, buffer, length);
  packet->length = length;

  netstar_capture_packet_build(packet, buffer, length);

  return packet;

_return:
  netstar_capture_packet_free(packet);
  return NULL;
}

static inline void
netstar_capture_packet_free(struct netstar_capture_packet *packet) {
  if (packet) {
    if (packet->ptr)
      free(packet->ptr), packet->ptr = NULL;

    free(packet);
  }
}

static void
netstar_capture_forward_loopback(netstar_t *netstar, uint8_t *buffer, size_t length) {
  struct netstar_capture_packet *packet = NULL;

  if (!(packet = netstar_capture_packet_new(buffer, length)))
    return;

  packet->type |= NETSTAR_FORWARD_LOOPBACK;

// netstar_capture_packets_add(packet);

// netstar_thread_routine(netstar_capture_packet_forward, packet);
  netstar_forward(netstar, packet);

  if (!(packet->flags & NETSTAR_CAPTURE_PACKET_LIVE))
    netstar_capture_packet_free(packet);
}

static void *
netstar_capture_loopback(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;
  netstar_t *netstar = (netstar_t *)thread->args;

  struct netpacket_timeout timeout = { .sec = 1, /* .usec = 1800 */ };

  uint8_t buffer[NETSTAR_CAPTURE_BUFFER_LENGTH] = {0};
//
// uint8_t *buffer = NULL;
//
// if (!(buffer = (uint8_t *)calloc(netstar->loopback_iface->mtu, sizeof(uint8_t))))
//   return NULL;
//
  ssize_t received = -1;

// netstar_log("#netstar-capture-loopback-thread started\r\n");

  for (; thread->status;) {
    if ((received = netstar_recv(&netstar->loopback, buffer, sizeof(buffer), &timeout)) <= 0)
      continue;

    netstar_capture_forward_loopback(netstar, buffer, (size_t)received);
  }

// netstar_log("#netstar-capture-loopback-thread exited\r\n");
  netstar_thread_exit(thread, NULL);
  return NULL;
}

static void
netstar_capture_forward(netstar_t *netstar, uint8_t *buffer, size_t length) {
  struct netstar_capture_packet *packet = NULL;

  if (!(packet = netstar_capture_packet_new(buffer, length)))
    return;

  if (netstar->forward)
    packet->flags |= NETSTAR_CAPTURE_PACKET_FORWARD;

// netstar_capture_packets_add(packet);

// netstar_thread_routine(netstar_capture_packet_forward, packet);
  netstar_forward(netstar, packet);

  if (!(packet->flags & NETSTAR_CAPTURE_PACKET_LIVE))
    netstar_capture_packet_free(packet);
}

static void *
netstar_capture(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;
  netstar_t *netstar = (netstar_t *)thread->args;

  struct netpacket_timeout timeout = { .sec = 1, /* .usec = 1800 */ };

  uint8_t buffer[NETSTAR_CAPTURE_BUFFER_LENGTH] = {0};
//
// uint8_t *buffer = NULL;
//
// if (!(buffer = (uint8_t *)calloc(netstar->managed.iface->mtu, sizeof(uint8_t))))
//   return NULL;
//
  ssize_t received = -1;

// netstar_log("#netstar-capture-thread started\r\n");

  for (; thread->status;) {
    if ((received = netstar_recv(&netstar->managed, buffer, sizeof(buffer), &timeout)) <= 0)
      continue;

    netstar_capture_forward(netstar, buffer, (size_t)received);
  }

// netstar_log("#netstar-capture-thread exited\r\n");
  netstar_thread_exit(thread, NULL);
  return NULL;
}


static netstar_thread_t *netstar_capture_loopback_thread;
static netstar_thread_t *netstar_capture_thread;


void
netstar_capture_start(netstar_t *netstar) {
  if (netstar_capture_started)
    return;

// if (!(netstar_capture_packets = netstar_capture_packets_new()))
 //  return;

  netstar_capture_loopback_thread = netstar_thread_spawn(netstar_capture_loopback, netstar);
  netstar_capture_thread = netstar_thread_spawn(netstar_capture, netstar);

  netstar_capture_started = true;
}

void
netstar_capture_stop(void) {
  if (!netstar_capture_started)
    return;

  netstar_thread_kill(netstar_capture_loopback_thread);
  netstar_thread_kill(netstar_capture_thread);

// netstar_capture_packets_free();

  netstar_capture_started = false;
}

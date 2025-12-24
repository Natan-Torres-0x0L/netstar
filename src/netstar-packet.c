#include "netstar-packet.h"

#include <collections/list/list.h>

#include <buffers/buffers.h>

#include <stdlib.h>
#include <string.h>

#define NETSTAR_PACKET_AUTOCHECKSUM true

typedef enum {
  NETSTAR_PACKET_BLOCK_PROTOCOL_ETHERNET,
  NETSTAR_PACKET_BLOCK_PROTOCOL_ARP,

  NETSTAR_PACKET_BLOCK_PROTOCOL_IPV4,
  NETSTAR_PACKET_BLOCK_PROTOCOL_IPV6,

  NETSTAR_PACKET_BLOCK_PROTOCOL_ICMPV4,
  NETSTAR_PACKET_BLOCK_PROTOCOL_ICMPV6,

  NETSTAR_PACKET_BLOCK_PROTOCOL_NDP = NETSTAR_PACKET_BLOCK_PROTOCOL_ICMPV6,
  NETSTAR_PACKET_BLOCK_PROTOCOL_NDP_OPTION,

  NETSTAR_PACKET_BLOCK_PROTOCOL_TCP,
  NETSTAR_PACKET_BLOCK_PROTOCOL_TCP_OPTION,

  NETSTAR_PACKET_BLOCK_PROTOCOL_UDP,
} netstar_packet_block_protocol_t;

struct netstar_packet_block {
  struct netstar_packet_block *parent, *reference;

  netstar_packet_block_protocol_t protocol;
  bool checksum;

  uint16_t length;

  buffer_t *buffer;
  buffer_t *payload;
};

struct netstar_packet {
  buffer_t *buffer;
  list_t *blocks;
};


static struct netstar_packet_block *netstar_packet_block_new(netstar_packet_t *, netstar_packet_block_protocol_t, uint16_t);
static void netstar_packet_block_free(void *);

static uint8_t
netstar_packet_block_protocol(netstar_packet_block_protocol_t protocol) {
  switch (protocol) {
    case NETSTAR_PACKET_BLOCK_PROTOCOL_ETHERNET:
    case NETSTAR_PACKET_BLOCK_PROTOCOL_ARP:
      break;

    case NETSTAR_PACKET_BLOCK_PROTOCOL_IPV4:
      return NETSTAR_IP_PROTOCOL_IPV4;

    case NETSTAR_PACKET_BLOCK_PROTOCOL_IPV6:
      return NETSTAR_IP_PROTOCOL_IPV6;

    case NETSTAR_PACKET_BLOCK_PROTOCOL_ICMPV4:
      return NETSTAR_IP_PROTOCOL_ICMPV4;

    case NETSTAR_PACKET_BLOCK_PROTOCOL_ICMPV6: // NETSTAR_PACKET_BLOCK_PROTOCOL_NDP:
      return NETSTAR_IP_PROTOCOL_ICMPV6;
    case NETSTAR_PACKET_BLOCK_PROTOCOL_NDP_OPTION:
      break;

    case NETSTAR_PACKET_BLOCK_PROTOCOL_TCP:
      return NETSTAR_IP_PROTOCOL_TCP;
    case NETSTAR_PACKET_BLOCK_PROTOCOL_TCP_OPTION:
      break;

    case NETSTAR_PACKET_BLOCK_PROTOCOL_UDP:
      return NETSTAR_IP_PROTOCOL_UDP;
  }

  return 0;
}

static struct netstar_packet_block *
netstar_packet_block_find(netstar_packet_t *packet, netstar_packet_block_t *block) {
  list_iterator_t blocks_iter = NULL;

  for (blocks_iter = list_begin(packet->blocks); blocks_iter; blocks_iter = list_next(blocks_iter))
    if (block == (netstar_packet_block_t *)list_value(blocks_iter))
      return block;

  return NULL;
}

static struct netstar_packet_block *
netstar_packet_block_protocol_find(struct netstar_packet_block *reference_block, netstar_packet_block_protocol_t protocol) {
  struct netstar_packet_block *block = reference_block->parent;

  for (; block; block = block->parent)
    if (block->protocol == protocol)
      return block;

  return NULL;
}

static inline bool
netstar_packet_block_is_ip(struct netstar_packet_block *block) {
  return (netstar_packet_block_protocol(block->protocol) == NETSTAR_IP_PROTOCOL_IPV4 || netstar_packet_block_protocol(block->protocol) == NETSTAR_IP_PROTOCOL_IPV6);
}

static inline uint8_t
netstar_packet_block_ip_version(struct netstar_iphdr *iph) {
  return ((iph->version == 6) ? NETSTAR_IP_PROTOCOL_IPV6 : NETSTAR_IP_PROTOCOL_IPV4);
}

static uint16_t
netstar_packet_block_ip_offset(uint8_t *buffer, list_iterator_t blocks_iter) {
  struct netstar_packet_block *block = NULL;
  uint16_t offset = 0;

  for (; blocks_iter; blocks_iter = list_prev(blocks_iter)) {
    block = (struct netstar_packet_block *)list_value(blocks_iter);

    offset += block->length;

    if (netstar_packet_block_is_ip(block))
      break;
  }

  return offset;
}

static struct netstar_packet_block *
netstar_packet_block_reference(netstar_packet_t *packet, netstar_packet_block_t *block, netstar_packet_block_protocol_t protocol, uint16_t length) {
  if (!(block = netstar_packet_block_find(packet, block)) && !(block = netstar_packet_block_new(packet, protocol, length)))
    return NULL;
  
  if (buffer_length(block->buffer) > length) {
    buffer_resize(block->buffer, length);
  }

  if (buffer_length(block->buffer)) {
    buffer_truncate(block->buffer, 0);

    block->protocol = protocol;
    block->length   = length;
  }

  return block;
}

static struct netstar_packet_block *
netstar_packet_block_new(netstar_packet_t *packet, netstar_packet_block_protocol_t protocol, uint16_t length) {
  struct netstar_packet_block *block = NULL;

  if (!(block = (struct netstar_packet_block *)calloc(1, sizeof(struct netstar_packet_block))))
    goto _return;

  if (!(block->buffer = buffer_new()))
    goto _return;

  if (!(block->payload = buffer_new()))
    goto _return;

  if (list_size(packet->blocks))
    block->parent = (struct netstar_packet_block *)list_value(list_end(packet->blocks));

  block->protocol = protocol;
  block->length   = length;

  list_pushback(packet->blocks, list_lvalue(block, sizeof(struct netstar_packet_block *)));

  return block;

_return:
  netstar_packet_block_free(block);
  return NULL;
}

static void
netstar_packet_block_free(void *value) {
  struct netstar_packet_block *block = (struct netstar_packet_block *)value;

  if (block) {
    buffer_free(block->buffer);
    buffer_free(block->payload);

    free(block);
  }
}

static uint16_t
netstar_checksum_carry(size_t sum) {
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return (uint16_t)~sum;
}

static uint32_t
netstar_checksum_add(const void *packet, uint16_t packet_length) {
  const uint8_t *data = (const uint8_t *)packet;
  uint32_t sum = 0;

  while (packet_length > 1) {
    sum += ((uint16_t)data[0] << 8) | data[1];
    data += 2;

    packet_length -= 2;
  }

  if (packet_length == 1)
    sum += ((uint16_t)data[0]) << 8;

  return sum;
}

static size_t
network_ipaddr_checksum(const void *buffer, uint16_t *packet, uint16_t packet_length) {
  struct netstar_iphdr *iph = (struct netstar_iphdr *)buffer;
  struct netstar_ipv6hdr *ipv6h = (struct netstar_ipv6hdr *)buffer;

  size_t sum = 0;

  switch (netstar_packet_block_ip_version(iph)) {
    case NETSTAR_IP_PROTOCOL_IPV6: {
      uint32_t length = htonl((uint32_t)packet_length), nexthdr = htonl((uint32_t)(ipv6h->nexthdr & 0xFF));

      sum += netstar_checksum_add((uint16_t *)&ipv6h->saddr, NETWORK_IPADDR6_SIZE);
      sum += netstar_checksum_add((uint16_t *)&ipv6h->daddr, NETWORK_IPADDR6_SIZE);

      sum += netstar_checksum_add((uint16_t *)&length, sizeof(length));
      sum += netstar_checksum_add((uint16_t *)&nexthdr, sizeof(nexthdr));

      break;
    }
 
    case NETSTAR_IP_PROTOCOL_IPV4: {
      sum += netstar_checksum_add((uint16_t *)&iph->saddr, NETWORK_IPADDR4_SIZE);
      sum += netstar_checksum_add((uint16_t *)&iph->daddr, NETWORK_IPADDR4_SIZE);

      sum += iph->protocol;
      sum += packet_length;

      break;
    }
  }

  sum += netstar_checksum_add(packet, packet_length);

  return sum;
}

static void
netstar_packet_do_checksum(uint8_t *buffer, uint16_t length, int protocol) {
  struct netstar_iphdr *iph = (struct netstar_iphdr *)buffer;
  struct netstar_ipv6hdr *ipv6h = NULL;

  size_t checksum;
  uint8_t ihl;

  switch (netstar_packet_block_ip_version(iph)) {
    case NETSTAR_IP_PROTOCOL_IPV6:
      ipv6h = (struct netstar_ipv6hdr *)buffer;
      ihl = NETSTAR_IPV6_SIZE;
      break;

    case NETSTAR_IP_PROTOCOL_IPV4:
      ihl = (uint8_t)(iph->ihl << 2);
      break;

    default:
      return;
  }

  switch (protocol) {
    case NETSTAR_IP_PROTOCOL_TCP: {
      struct netstar_tcphdr *tcph = (struct netstar_tcphdr *)(buffer+ihl);

      tcph->checksum = 0, checksum = 0;

      length = (length-NETSTAR_TCP_SIZE)+tcph->data_offset*4;

      checksum += network_ipaddr_checksum(iph, (uint16_t *)tcph, length);
      checksum = (size_t)netstar_checksum_carry(checksum);

      tcph->checksum = (uint16_t)htons(checksum);
      break;
    }

    case NETSTAR_IP_PROTOCOL_UDP: {
      struct netstar_udphdr *udph = (struct netstar_udphdr *)(buffer+ihl);

      udph->checksum = 0, checksum = 0;

      checksum += network_ipaddr_checksum(iph, (uint16_t *)udph, length);
      checksum = (size_t)netstar_checksum_carry(checksum);

      udph->checksum = (uint16_t)htons(checksum);
      break;
    }

    case NETSTAR_IP_PROTOCOL_ICMPV4: {
      struct netstar_icmphdr *icmph = (struct netstar_icmphdr *)(buffer+ihl);

      icmph->checksum = 0, checksum = 0;
      length = (uint16_t)(buffer+ntohs(iph->length)-(uint8_t *)icmph);

      checksum = netstar_checksum_add((uint16_t *)icmph, length);
      checksum = (size_t)netstar_checksum_carry(checksum);

      icmph->checksum = (uint16_t)htons(checksum);
      break;
    }

    case NETSTAR_IP_PROTOCOL_ICMPV6: {
      struct netstar_icmpv6hdr *icmp6h = (struct netstar_icmpv6hdr *)(buffer+ihl);

      icmp6h->checksum = 0, checksum = 0;
      length = (uint16_t)ntohs(ipv6h->length);

      checksum = network_ipaddr_checksum(ipv6h, (uint16_t *)icmp6h, length);
      checksum = (size_t)netstar_checksum_carry(checksum);

      icmp6h->checksum = (uint16_t)htons(checksum);
      break;
    }

    case NETSTAR_IP_PROTOCOL_IPV4: {
      iph->checksum = 0, checksum = 0;

      checksum = netstar_checksum_add((uint16_t *)iph, length);
      checksum = (size_t)netstar_checksum_carry(checksum);

      iph->checksum = (uint16_t)htons(checksum);
      break;
    }
  }
}

void
netstar_packet_coalesce(netstar_packet_t *packet) {
  list_iterator_t blocks_iter = NULL, reference_blocks_iter = NULL;
  struct netstar_packet_block *block = NULL;

  uint8_t *buffer = NULL;
  size_t references;

  buffer_truncate(packet->buffer, 0);

  for (blocks_iter = list_begin(packet->blocks); blocks_iter; blocks_iter = list_next(blocks_iter)) {
    block = (struct netstar_packet_block *)list_value(blocks_iter);

    buffer_append(packet->buffer, buffer_ptr(block->buffer), buffer_length(block->buffer));

    for (reference_blocks_iter = list_next(blocks_iter), references = 0; reference_blocks_iter; reference_blocks_iter = list_next(reference_blocks_iter)) {
      struct netstar_packet_block *reference_block = (struct netstar_packet_block *)list_value(reference_blocks_iter);

      if (reference_block->reference != block)
        break;

      buffer_append(packet->buffer, buffer_ptr(reference_block->buffer), buffer_length(reference_block->buffer));
      references++;
    }
    if (references)
      blocks_iter = reference_blocks_iter;

    if (buffer_length(block->payload))
      buffer_append(packet->buffer, buffer_ptr(block->payload), buffer_length(block->payload));
  }

  buffer = (uint8_t *)buffer_ptr(packet->buffer)+buffer_length(packet->buffer);

  for (blocks_iter = list_end(packet->blocks); blocks_iter; blocks_iter = list_prev(blocks_iter)) {
    block = (struct netstar_packet_block *)list_value(blocks_iter);

    if (block->checksum == NETSTAR_PACKET_AUTOCHECKSUM) {
      netstar_packet_do_checksum(
        buffer-netstar_packet_block_ip_offset(buffer, blocks_iter),
        block->length,
        netstar_packet_block_protocol(block->protocol)
      );
    }

    buffer -= block->length;
  }
}

netstar_packet_block_t *
netstar_packet_buildethernet(netstar_packet_t *packet, netstar_packet_block_t *rblock, const network_macaddr_t *dhardware, const network_macaddr_t *shardware, uint16_t type, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_ethernethdr etherneth = {0};

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_ETHERNET, NETSTAR_ETHERNET_SIZE+payload_length)))
    return NULL;

  memset(&etherneth, 0, NETSTAR_ETHERNET_SIZE);
  memcpy(etherneth.dhardware, dhardware, NETWORK_MACADDR_SIZE);
  memcpy(etherneth.shardware, shardware, NETWORK_MACADDR_SIZE);
  etherneth.type = htons(type);

  buffer_append(block->buffer, &etherneth, NETSTAR_ETHERNET_SIZE);

  if (payload && payload_length)
    buffer_append(block->payload, payload, payload_length);

  return block;
}

netstar_packet_block_t *
netstar_packet_buildarp(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint16_t hardware, uint16_t protocol, uint8_t hardware_size, uint8_t protocol_size, uint16_t opcode, const network_macaddr_t *shardware, const network_ipaddr4_t *saddr, const network_macaddr_t *dhardware, const network_ipaddr4_t *daddr, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_arphdr arph = {0};

  network_macaddr_t dmac = {0};

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_ARP, NETSTAR_ARP_SIZE+payload_length)))
    return NULL;

  if (!(opcode == NETSTAR_ARP_OPCODE_REQUEST && !memcmp(dhardware, &MACIEEE802_BROADCAST, NETWORK_MACADDR_SIZE)))
    dmac = *dhardware;

  memset(&arph, 0, NETSTAR_ARP_SIZE);
  arph.hardware      = htons(hardware);
  arph.protocol      = htons(protocol);
  arph.hardware_size = hardware_size;
  arph.protocol_size = protocol_size;
  arph.opcode        = htons(opcode);
  memcpy(arph.shardware, shardware, NETWORK_MACADDR_SIZE);
  memcpy(arph.saddr, saddr, NETWORK_IPADDR4_SIZE);
  memcpy(arph.dhardware, &dmac, NETWORK_MACADDR_SIZE);
  memcpy(arph.daddr, daddr, NETWORK_IPADDR4_SIZE);

  buffer_append(block->buffer, &arph, NETSTAR_ARP_SIZE);

// buffer_append(block->buffer, &arph, NETSTAR_ARP_SIZE-((NETWORK_MACADDR_SIZE*2)+(NETWORK_IPADDR4_SIZE*2)));
//
// buffer_append(block->buffer, shardware, hardware_size);
// buffer_append(block->buffer, saddr, protocol_size);
// buffer_append(block->buffer, dhardware, hardware_size);
// buffer_append(block->buffer, daddr, protocol_size);

  if (payload && payload_length)
    buffer_append(block->payload, payload, payload_length);

  return block;
}

netstar_packet_block_t *
netstar_packet_buildipv4(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t typeof_service, uint16_t length, uint16_t id, uint16_t fragment_offset, uint8_t ttl, uint8_t protocol, uint16_t checksum, const network_ipaddr4_t *saddr, const network_ipaddr4_t *daddr, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_iphdr iph = {0};

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_IPV4, NETSTAR_IP_SIZE+payload_length)))
    return NULL;

  memset(&iph, 0, NETSTAR_IP_SIZE);
  iph.version         = 4;
  iph.ihl             = 5;
  iph.typeof_service  = typeof_service;
  iph.length          = htons(length);
  iph.id              = htons(id);
  iph.fragment_offset = htons(fragment_offset);
  iph.ttl             = ttl;
  iph.protocol        = protocol;
  iph.checksum        = ((checksum) ? htons(checksum) : 0);
  memcpy(iph.saddr, saddr, NETWORK_IPADDR4_SIZE);
  memcpy(iph.daddr, daddr, NETWORK_IPADDR4_SIZE);

  buffer_append(block->buffer, &iph, NETSTAR_IP_SIZE);

  if (payload && payload_length)
    buffer_append(block->payload, payload, payload_length);

  if (!checksum)
    block->checksum = NETSTAR_PACKET_AUTOCHECKSUM;

  return block;
}

netstar_packet_block_t *
netstar_packet_buildipv6(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t priority, uint32_t flow_label, uint16_t length, uint8_t nexthdr, uint8_t hop_limit, const network_ipaddr6_t *saddr, const network_ipaddr6_t *daddr, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_ipv6hdr ipv6h = {0};

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_IPV6, NETSTAR_IPV6_SIZE+payload_length)))
    return NULL;

  memset(&ipv6h, 0, NETSTAR_IPV6_SIZE);
  ipv6h.version       = 6;
  ipv6h.priority      = (uint8_t)(priority & 0x0F);
  ipv6h.flow_label[0] = ((flow_label & 0xF0000) >> 16);
  ipv6h.flow_label[1] = (flow_label & 0x0FF00 >> 8);
  ipv6h.flow_label[2] = (flow_label & 0x000FF);
  ipv6h.length        = htons(length);
  ipv6h.nexthdr       = nexthdr;
  ipv6h.hop_limit     = hop_limit;
  memcpy(ipv6h.saddr, saddr, NETWORK_IPADDR6_SIZE);
  memcpy(ipv6h.daddr, daddr, NETWORK_IPADDR6_SIZE);

  buffer_append(block->buffer, &ipv6h, NETSTAR_IPV6_SIZE);

  if (payload && payload_length)
    buffer_append(block->payload, payload, payload_length);

  return block;
}

static netstar_packet_block_t *
netstar_packet_buildicmp(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t type, uint8_t code, uint16_t checksum, const void *specific, uint16_t specific_size, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_icmphdr icmph = {0};

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_ICMPV4, (uint16_t)(NETSTAR_ICMP_SIZE+specific_size+payload_length))))
    return NULL;

  icmph.type     = type;
  icmph.code     = code;
  icmph.checksum = ((checksum) ? htons(checksum) : 0);

  buffer_append(block->buffer, &icmph, NETSTAR_ICMP_SIZE);

  if (specific && specific_size)
    buffer_append(block->buffer, specific, specific_size);

  if (payload && payload_length)
    buffer_append(block->payload, payload, payload_length);

  if (!checksum)
    block->checksum = NETSTAR_PACKET_AUTOCHECKSUM;

  return block;
}

netstar_packet_block_t *
netstar_packet_buildicmpecho(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t type, uint8_t code, uint16_t checksum, uint16_t id, uint16_t sequence, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_icmp_echo echo = {0};

  echo.id       = htons(id);
  echo.sequence = htons(sequence);

  if (!(block = netstar_packet_buildicmp(packet, rblock, type, code, checksum, &echo, NETSTAR_ICMP_ECHO_SIZE, payload, payload_length)))
    return NULL;

  return block;
}

netstar_packet_block_t *
netstar_packet_buildicmpredirect(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t type, uint8_t code, const network_ipaddr4_t *gateway, uint16_t checksum, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_icmp_redirect redirect = {0};

  memcpy(redirect.gateway, gateway, NETWORK_IPADDR4_SIZE);

  if (!(block = netstar_packet_buildicmp(packet, rblock, type, code, checksum, &redirect, NETSTAR_ICMP_REDIRECT_SIZE, payload, payload_length)))
    return NULL;

  return block;
}

static netstar_packet_block_t *
netstar_packet_buildicmpv6(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t type, uint8_t code, uint16_t checksum, const void *specific, uint16_t specific_size, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_icmpv6hdr icmpv6h = {0};

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_ICMPV6, (uint16_t)(NETSTAR_ICMPV6_SIZE+specific_size+payload_length))))
    return NULL;

  icmpv6h.type     = type;
  icmpv6h.code     = code;
  icmpv6h.checksum = ((checksum) ? htons(checksum) : 0);
 
  buffer_append(block->buffer, &icmpv6h, NETSTAR_ICMPV6_SIZE);

  if (specific && specific_size)
    buffer_append(block->buffer, specific, specific_size);

  if (payload && payload_length)
    buffer_append(block->payload, payload, payload_length);

  if (!checksum)
    block->checksum = NETSTAR_PACKET_AUTOCHECKSUM;

  return block;
}

netstar_packet_block_t *
netstar_packet_buildicmpv6echo(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t type, uint8_t code, uint16_t checksum, uint16_t id, uint16_t sequence, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_icmpv6_echo echo = {0};

  echo.id       = htons(id);
  echo.sequence = htons(sequence);

  if (!(block = netstar_packet_buildicmpv6(packet, rblock, type, code, checksum, &echo, NETSTAR_ICMPV6_ECHO_SIZE, payload, payload_length)))
    return NULL;

  return block;
}

netstar_packet_block_t *
netstar_packet_buildndpsolicit(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t type, uint8_t code, uint16_t checksum, const network_ipaddr6_t *daddr, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_ndp_solicit solicit = {0};

  solicit.reserved = 0;
  memcpy(&solicit.daddr, daddr, NETWORK_IPADDR6_SIZE);

  if (!(block = netstar_packet_buildicmpv6(packet, rblock, type, code, checksum, &solicit, NETSTAR_NDP_SOLICIT_SIZE, payload, payload_length)))
    return NULL;

  return block;
}

netstar_packet_block_t *
netstar_packet_buildndpadvert(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t type, uint8_t code, uint16_t checksum, uint32_t flags, const network_ipaddr6_t *saddr, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_ndp_advert advert = {0};

  advert.flags = htonl(flags);
  memcpy(&advert.saddr, saddr, NETWORK_IPADDR6_SIZE);

  if (!(block = netstar_packet_buildicmpv6(packet, rblock, type, code, checksum, &advert, NETSTAR_NDP_ADVERT_SIZE, payload, payload_length)))
    return NULL;

  return block;
}

netstar_packet_block_t *
netstar_packet_buildndpoption(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint8_t type, const void *target_option, uint8_t target_option_size) {
  struct netstar_packet_block *block = NULL;
  struct netstar_ndp_option option = {0};

  static const uint8_t padding[8] = {0};
  size_t padding_size = 0;
  size_t length = 0;

  if ((length = NETSTAR_NDP_OPTION_SIZE+target_option_size) % 8)
    length += 8-(length % 8);

  if (length > NETSTAR_NDP_OPTIONS_SIZE)
    return NULL;

  padding_size = length-target_option_size-NETSTAR_NDP_OPTION_SIZE;

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_NDP_OPTION, (uint16_t)length)))
    return NULL;

  memset(&option, 0, NETSTAR_NDP_OPTION_SIZE);
  option.type   = type;
  option.length = (uint8_t)(length / 8);

  buffer_append(block->buffer, &option, NETSTAR_NDP_OPTION_SIZE);
  buffer_append(block->buffer, target_option, target_option_size);
  buffer_append(block->buffer, padding, padding_size);

  return block;
}

netstar_packet_block_t *
netstar_packet_buildtcp(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint16_t sport, uint16_t dport, uint32_t sequence, uint32_t acknowledgment, uint8_t flags, uint16_t window, uint16_t urgentptr, uint16_t checksum, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_tcphdr tcph = {0};

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_TCP, NETSTAR_TCP_SIZE+payload_length)))
    return NULL;

  memset(&tcph, 0, NETSTAR_TCP_SIZE);
  tcph.sport          = htons(sport);
  tcph.dport          = htons(dport);
  tcph.sequence       = htonl(sequence);
  tcph.acknowledgment = htonl(acknowledgment);
  tcph.data_offset    = 5;
  tcph.reserved       = 0;
// tcph.fin            = (flags & NETSTAR_TCP_FLAGS_FIN);
// tcph.syn            = (flags & NETSTAR_TCP_FLAGS_SYN);
// tcph.rst            = (flags & NETSTAR_TCP_FLAGS_RST);
// tcph.psh            = (flags & NETSTAR_TCP_FLAGS_PSH);
// tcph.ack            = (flags & NETSTAR_TCP_FLAGS_ACK);
// tcph.urg            = (flags & NETSTAR_TCP_FLAGS_URG);
// tcph.ece            = 0;
// tcph.cwr            = 0;
  tcph.flags          = flags;
  tcph.window         = htons(window);
  tcph.urgentptr      = htons(urgentptr);
  tcph.checksum       = ((checksum) ? htons(checksum) : 0);

  buffer_append(block->buffer, &tcph, NETSTAR_TCP_SIZE);

  if (payload && payload_length)
    buffer_append(block->payload, payload, payload_length);

  if (!checksum)
    block->checksum = NETSTAR_PACKET_AUTOCHECKSUM;

  return block;
}

netstar_packet_block_t *
netstar_packet_buildtcpoptions(netstar_packet_t *packet, netstar_packet_block_t *rblock, const uint8_t *options, uint8_t options_size) {
  struct netstar_packet_block *block = NULL, *branch_block = NULL;
  struct netstar_tcphdr *tcph = NULL;

  if ((!(options_size % 4 == 0) && !(options_size -= (options_size % 4))) || options_size > NETSTAR_TCP_OPTIONS_SIZE)
    return NULL;

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_TCP_OPTION, options_size)))
    return NULL;

  if ((branch_block = netstar_packet_block_protocol_find(block, NETSTAR_PACKET_BLOCK_PROTOCOL_TCP))) {
    tcph = (struct netstar_tcphdr *)buffer_ptr(branch_block->buffer);
    tcph->data_offset += options_size/4;

 // branch_block->length = tcph->data_offset*4;
    block->reference = branch_block;
  }

  buffer_append(block->buffer, options, options_size);

  return block;
}

netstar_packet_block_t *
netstar_packet_buildudp(netstar_packet_t *packet, netstar_packet_block_t *rblock, uint16_t sport, uint16_t dport, uint16_t length, uint16_t checksum, uint8_t *payload, uint16_t payload_length) {
  struct netstar_packet_block *block = NULL;
  struct netstar_udphdr udph = {0};

  if (!(block = netstar_packet_block_reference(packet, rblock, NETSTAR_PACKET_BLOCK_PROTOCOL_UDP, length)))
    return NULL;

  memset(&udph, 0, NETSTAR_UDP_SIZE);
  udph.sport    = htons(sport);
  udph.dport    = htons(dport);
  udph.length   = htons(length);
  udph.checksum = ((checksum) ? htons(checksum) : 0);

  buffer_append(block->buffer, &udph, NETSTAR_UDP_SIZE);

  if (payload && payload_length)
    buffer_append(block->payload, payload, payload_length);

  if (!checksum)
    block->checksum = NETSTAR_PACKET_AUTOCHECKSUM;

  return block;
}

uint8_t *
netstar_packet_buffer(netstar_packet_t *packet) {
  return (uint8_t *)buffer_ptr(packet->buffer);
}

size_t
netstar_packet_length(netstar_packet_t *packet) {
  return buffer_length(packet->buffer);
}

netstar_packet_t *
netstar_packet_new(void) {
  netstar_packet_t *packet = NULL;

  if (!(packet = (netstar_packet_t *)calloc(1, sizeof(struct netstar_packet))))
    goto _return;

  if (!(packet->buffer = buffer_new()))
    goto _return;

  if (!(packet->blocks = list_new(netstar_packet_block_free)))
    goto _return;

  return packet;

_return:
  netstar_packet_free(packet);
  return NULL;
}

void
netstar_packet_free(netstar_packet_t *packet) {
  if (packet) {
    if (packet->buffer)
      buffer_free(packet->buffer), packet->buffer = NULL;
    if (packet->blocks)
      list_free(packet->blocks), packet->blocks = NULL;

    free(packet);
  }
}

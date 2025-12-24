#include "netstar-scanner.h"

#include <netstar-services.h>
#include <netstar-threads.h>

#include <netstar-forward.h>

#include <netstar-vendors.h>

#include <netstar-utils.h>
#include <netstar-time.h>

#include <netstar.h>


static bool netstar_scanner_initialized, netstar_scanner_started;

static netstar_thread_t *netstar_scanner_hosts4_send_thread;
netstar_hosts_t netstar_scanner_scanned_hosts4;

static netstar_thread_t *netstar_scanner_hosts6_send_thread;
netstar_hosts_t netstar_scanner_scanned_hosts6;


static void
netstar_scanner_hosts4_recv(netstar_t *netstar, struct netstar_capture_packet *packet, void *args) {
  struct netstar_scanner *scanner = (struct netstar_scanner *)args;
  netstar_host_t host = {0};

  if (netstar_host_new(&host, &packet->layer2.smac, &packet->layer3.saddr, NETWORK_IPADDR4) == -1)
    return;

  if (!network_macaddr_compare(&host.mac, &netstar->managed.iface->mac) || !network_ipaddr4_compare(&host.addr.v4, &netstar->managed.iface->addr))
    return;
  if (network_ipaddr4_compare(&host.addr.v4, &scanner->hosts4.range.begin) == -1 || network_ipaddr4_compare(&host.addr.v4, &scanner->hosts4.range.end) == 1)
    return;

  if (scanner->preexcluded_hosts && netstar_hosts_findmac(scanner->preexcluded_hosts, &host.mac))
    return;
  if (scanner->preexcluded_hosts && netstar_hosts_findipaddr4(scanner->preexcluded_hosts, &host.addr.v4))
    return;

  if (netstar_hosts_add(netstar_scanner_scanned_hosts4, &host) != -1 && !scanner->silent) {
    char mac[NETWORK_MACADDR_STRLENGTH] = {0}, addr[NETWORK_IPADDR6_STRLENGTH] = {0};
    const char *vendor = NULL;

    network_macaddr_format(&host.mac, mac, sizeof(mac));
    vendor = netstar_vendors_namebymac(&host.mac);

    network_ipaddr4_format(&host.addr.v4, addr, sizeof(addr));

    netstar_log("\b \b[ scanner@hosts4 ] %s  %s  %s\r\n", mac, addr, vendor);
  }
}

static void *
netstar_scanner_hosts4_send(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;
  struct netstar_scanner *scanner = (struct netstar_scanner *)thread->args;
  netstar_t *netstar = scanner->netstar;

  netstar_timer_t timer = NETSTAR_TIMER_INITIALIZER;

  if (network_ipaddr4_isclassa(&scanner->hosts4.range.begin) && ntohl(scanner->hosts4.range.end.u32)-ntohl(scanner->hosts4.range.begin.u32) >= 6048) // !network_ipaddr4_compare(&netstar->managed.iface->network, &scanner->hosts4.range.begin) && !network_ipaddr4_compare(&netstar->managed.iface->broadcast, &scanner->hosts4.range.end))
    netstar_warning("\b \b[ scanner@hosts4 ]: network class A - %u hosts; consider using a range or a more specific CIDR block to avoid unnecessarily large address spaces\r\n", ntohl(scanner->hosts4.range.end.u32)-ntohl(scanner->hosts4.range.begin.u32));

  {
    char begin_addr[NETWORK_IPADDR4_STRLENGTH] = {0}, end_addr[NETWORK_IPADDR4_STRLENGTH] = {0};

    netstar_log("\b \b[ scanner@hosts4 ]: scan-range: %s - %s; scan-interval: %" PRIu32 "s\r\n",
      network_ipaddr4_format(&scanner->hosts4.range.begin, begin_addr, sizeof(begin_addr)),
      network_ipaddr4_format(&scanner->hosts4.range.end, end_addr, sizeof(end_addr)),
      netstar_time_millisecstosecs(scanner->hosts4.time_interval));
  }

  for (; thread->status;) {
    netstar_time_t remaining_time = netstar_timer(&timer);

    if (!remaining_time) {
      network_ipaddr4_t addr = {0};

      for (addr = scanner->hosts4.range.begin; thread->status && addr.u32 < scanner->hosts4.range.end.u32; addr.u32 = htonl(ntohl(addr.u32)+1)) {
        if (!network_ipaddr4_compare(&netstar->managed.iface->addr, &addr) || netstar_hosts_findipaddr4(netstar_scanner_scanned_hosts4, &addr))
          continue;
        if (addr.u8[3] == 255 || addr.u8[3] == 0)
          continue;

        if (netstar_hosts_size(scanner->preexcluded_hosts) && netstar_hosts_findipaddr4(scanner->preexcluded_hosts, &addr))
          continue;

        if (addr.u8[3] == 255/4 || addr.u8[3] == 255/2)
          netstar_time_sleep(870);

        netstar_sendarp(&netstar->managed, &netstar->managed.iface->mac, &MACIEEE802_BROADCAST, NETSTAR_ARP_OPCODE_REQUEST, &netstar->managed.iface->mac, &netstar->managed.iface->addr, &MACIEEE802_BROADCAST, &addr);

        netstar_time_sleep(20);
      }

      netstar_timer_start(&timer, netstar_time_millisecstosecs(scanner->hosts4.time_interval));
    }

    if (!thread->status)
      break;

    netstar_time_sleep(netstar_time_secstomillisecs(1));
  }

  netstar_thread_exit(thread, NULL);
  return NULL;
}

static void
netstar_scanner_hosts6_recv(netstar_t *netstar, struct netstar_capture_packet *packet, void *args) {
  struct netstar_scanner *scanner = (struct netstar_scanner *)args;
  netstar_host_t host = {0};

  if (netstar_host_new(&host, &packet->layer2.smac, &packet->layer3.saddr, NETWORK_IPADDR6) == -1)
    return;

  if (!network_macaddr_compare(&host.mac, &netstar->managed.iface->mac) || !network_ipaddr6_compare(&host.addr.v6, &netstar->managed.iface->addr6))
    return;
  if (network_ipaddr6_compare(&host.addr.v6, &scanner->hosts6.range.begin) == -1 || network_ipaddr6_compare(&host.addr.v6, &scanner->hosts6.range.end) == 1)
    return;

  if (scanner->preexcluded_hosts && netstar_hosts_findmac(scanner->preexcluded_hosts, &host.mac))
    return;
  if (scanner->preexcluded_hosts && netstar_hosts_findipaddr6(scanner->preexcluded_hosts, &host.addr.v6))
   return;

  if (netstar_hosts_add(netstar_scanner_scanned_hosts6, &host) != -1 && !scanner->silent) {
    char mac[NETWORK_MACADDR_STRLENGTH] = {0}, addr[NETWORK_IPADDR6_STRLENGTH] = {0};
    const char *vendor = NULL;

    network_macaddr_format(&host.mac, mac, sizeof(mac));
    vendor = netstar_vendors_namebymac(&host.mac);

    network_ipaddr6_format(&host.addr.v6, addr, sizeof(addr));

    netstar_log("\b \b[ scanner@hosts6 ] %s  %s  %s\r\n", mac, addr, vendor);
  }
}

static void *
netstar_scanner_hosts6_send(void *context) {
  netstar_thread_t *thread = (netstar_thread_t *)context;
  struct netstar_scanner *scanner = (struct netstar_scanner *)thread->args;
  netstar_t *netstar = scanner->netstar;

  netstar_timer_t timer = NETSTAR_TIMER_INITIALIZER;

  {
    char begin_addr[NETWORK_IPADDR6_STRLENGTH] = {0}, end_addr[NETWORK_IPADDR6_STRLENGTH] = {0};

    netstar_log("\b \b[ scanner@hosts6 ]: scan-range: %s - %s; scan-interval: %" PRIu32 "s\r\n",
      network_ipaddr6_format(&scanner->hosts6.range.begin, begin_addr, sizeof(begin_addr)),
      network_ipaddr6_format(&scanner->hosts6.range.end, end_addr, sizeof(end_addr)),
      netstar_time_millisecstosecs(scanner->hosts6.time_interval));
  }

  for (; thread->status;) {
    netstar_time_t remaining_time = netstar_timer(&timer);

    if (!remaining_time) {
      netstar_sendicmpv6echo(&netstar->managed, &netstar->managed.iface->mac, &MACIEEE802_V6ALLNODES, NETSTAR_ICMPV6_TYPE_ECHO, &netstar->managed.iface->addr6, &NETWORK_IPADDR6_ALLNODES);

      netstar_timer_start(&timer, netstar_time_millisecstosecs(scanner->hosts6.time_interval));
    }

    netstar_time_sleep(netstar_time_secstomillisecs(2));
  }

  netstar_thread_exit(thread, NULL);
  return NULL;
}

int
netstar_scanner_new(struct netstar_scanner *scanner, netstar_t *netstar) {
  if (!(scanner->preexcluded_hosts = netstar_hosts_new()))
    goto _return;

  scanner->hosts4.time_interval = netstar_time_minutestomillisecs(4);
  scanner->hosts6.time_interval = netstar_time_minutestomillisecs(6);

  scanner->netstar = netstar;

  return 1;

_return:
  netstar_scanner_free(scanner);
  return -1;
}

void
netstar_scanner_free(struct netstar_scanner *scanner) {
  if (scanner) {
    netstar_hosts_free(scanner->preexcluded_hosts);
  }
}

__attribute__((__constructor__))
static void
netstar_scanner_scanned_hosts_initialize(void) {
  if (!netstar_scanner_scanned_hosts4 && !(netstar_scanner_scanned_hosts4 = netstar_hosts_new()))
    netstar_critical("");

  if (!netstar_scanner_scanned_hosts6 && !(netstar_scanner_scanned_hosts6 = netstar_hosts_new()))
    netstar_critical("");
}

void
netstar_scanner_initialize(netstar_t *netstar, void *context) {
  struct netstar_scanner *scanner = (struct netstar_scanner *)context;

  if (netstar_scanner_initialized)
    return;

  if (!network_ipaddr4_compare(&scanner->hosts4.range.begin, &NETWORK_IPADDR4_ANY) || !network_ipaddr4_compare(&scanner->hosts4.range.end, &NETWORK_IPADDR4_ANY))
    netstar_utils_ranges_ipaddr4(&netstar->managed.iface->network, netstar->managed.iface->prefix, &scanner->hosts4.range.begin, &scanner->hosts4.range.end);

  if (scanner->mode & NETSTAR_SCANNER_MODE_HOSTS4)
    netstar_forward_add(netstar_scanner_hosts4_recv, NETSTAR_FORWARD_ALL, scanner);

  if (!network_ipaddr6_compare(&scanner->hosts6.range.begin, &NETWORK_IPADDR6_ANY) || !network_ipaddr6_compare(&scanner->hosts6.range.end, &NETWORK_IPADDR6_ANY))
    netstar_utils_ranges_ipaddr6(&netstar->managed.iface->network6, netstar->managed.iface->prefix6, &scanner->hosts6.range.begin, &scanner->hosts6.range.end);

  if (scanner->mode & NETSTAR_SCANNER_MODE_HOSTS6)
    netstar_forward_add(netstar_scanner_hosts6_recv, NETSTAR_FORWARD_ALL, scanner);

  if (!scanner->silent)
    netstar_vendors_initialize();

  netstar_scanner_initialized = true;
  return;

_return:
  netstar_hosts_free(netstar_scanner_scanned_hosts4);
  netstar_hosts_free(netstar_scanner_scanned_hosts6);
}

__attribute__((__destructor__))
static void
netstar_scanner_scanned_hosts_deinitialize(void) {
  netstar_hosts_free(netstar_scanner_scanned_hosts4);
  netstar_scanner_scanned_hosts4 = NULL;

  netstar_hosts_free(netstar_scanner_scanned_hosts6);
  netstar_scanner_scanned_hosts6 = NULL;
}

void
netstar_scanner_deinitialize(void *context) {
  struct netstar_scanner *scanner = (struct netstar_scanner *)context;

  if (!netstar_scanner_initialized)
    return;

  netstar_forward_remove(netstar_scanner_hosts4_recv);
  netstar_forward_remove(netstar_scanner_hosts6_recv);

  netstar_scanner_free(scanner);

  netstar_vendors_deinitialize();

  netstar_scanner_initialized = false;
}

void
netstar_scanner_start(void *context) {
  struct netstar_scanner *scanner = (struct netstar_scanner *)context;

  if (netstar_scanner_started)
    return;

  netstar_scanner_started = true;

  if (scanner->mode & NETSTAR_SCANNER_MODE_STEALTH)
    return;

  if (scanner->mode & NETSTAR_SCANNER_MODE_HOSTS4)
    netstar_scanner_hosts4_send_thread = netstar_thread_spawn(netstar_scanner_hosts4_send, scanner);

  if (scanner->mode & NETSTAR_SCANNER_MODE_HOSTS6)
    netstar_scanner_hosts6_send_thread = netstar_thread_spawn(netstar_scanner_hosts6_send, scanner);
}

void
netstar_scanner_stop(void *context) {
  if (!netstar_scanner_started)
    return;

  netstar_thread_kill(netstar_scanner_hosts4_send_thread);
  netstar_thread_kill(netstar_scanner_hosts6_send_thread);

  netstar_scanner_started = false;
}

static struct netstar_scanner netstar_scanner = {
  .mode = NETSTAR_SCANNER_MODE_NETWORK, .silent = true,
};

static struct netstar_service netstar_scanner_module_service = {
  netstar_scanner_initialize, netstar_scanner_deinitialize,
  netstar_scanner_start, netstar_scanner_stop,
  "netstar:scanner", &netstar_scanner,
  NETSTAR_SERVICE_FLAGS_INITIALIZE
};

struct netstar_service *
netstar_scanner_service(void) {
  return &netstar_scanner_module_service;
}

__attribute__((__constructor__))
static inline void
netstar_scanner_register_service(void) {
  netstar_services_register(netstar_scanner_service());
}

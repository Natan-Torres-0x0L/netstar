#ifndef _NETSTAR_ARP_SPOOFING_H
#define _NETSTAR_ARP_SPOOFING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netstar-threads.h>
#include <netstar-time.h>

#include <netstar-hosts.h>

#include <netstar.h>


struct netstar_arp_broadcast_spoofing {
  netstar_hosts_t spoofed_hosts;

  netstar_time_t spoof_burst_interval;
  size_t spoof_burst_count;

  netstar_time_t spoof_steady_interval;

  netstar_thread_t *thread;

  netstar_t *netstar;
};


extern int netstar_arp_broadcast_spoofing_new(struct netstar_arp_broadcast_spoofing *, netstar_t *);
extern void netstar_arp_broadcast_spoofing_free(struct netstar_arp_broadcast_spoofing *);


struct netstar_arp_network_spoofing {
  netstar_hosts_t protected_hosts, spoofed_hosts;

  bool bidirectional;

  netstar_host_t redirection_host;
  bool redirective;

  netstar_time_t network_scan_interval;

  netstar_time_t spoof_burst_interval;
  size_t spoof_burst_count;

  netstar_time_t spoof_steady_interval;

  bool request;

  netstar_thread_t *thread;

  netstar_t *netstar;
};


extern int netstar_arp_network_spoofing_new(struct netstar_arp_network_spoofing *, netstar_t *);
extern void netstar_arp_network_spoofing_free(struct netstar_arp_network_spoofing *);


struct netstar_arp_spoofing {
  netstar_hosts_t spoofed_hosts, target_hosts;

  bool bidirectional;

  netstar_host_t redirection_host;
  bool redirective;

  netstar_time_t spoof_burst_interval;
  size_t spoof_burst_count;

  netstar_time_t spoof_steady_interval;

  bool request;

  netstar_thread_t *thread;

  netstar_t *netstar;
};


extern int netstar_arp_spoofing_new(struct netstar_arp_spoofing *, netstar_t *);
extern void netstar_arp_spoofing_free(struct netstar_arp_spoofing *);

#ifdef __cplusplus
}
#endif

#endif

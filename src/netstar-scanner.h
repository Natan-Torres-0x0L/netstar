#ifndef _NETSTAR_SCANNER_H
#define _NETSTAR_SCANNER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netstar-hosts.h>
#include <netstar-time.h>

#include <netstar.h>

typedef enum {
  NETSTAR_SCANNER_MODE_HOSTS4  = 0x01,
  NETSTAR_SCANNER_MODE_HOSTS6  = 0x02,
  NETSTAR_SCANNER_MODE_NETWORK = (NETSTAR_SCANNER_MODE_HOSTS4|NETSTAR_SCANNER_MODE_HOSTS6),
  NETSTAR_SCANNER_MODE_STEALTH = 0x04
} netstar_scanner_mode_t;

struct netstar_scanner {
  netstar_hosts_t preexcluded_hosts;

  netstar_scanner_mode_t mode;

  struct {
    netstar_network_ipaddr4_range_t range;
    netstar_time_t time_interval;
  } hosts4;

  struct {
    netstar_network_ipaddr6_range_t range;
    netstar_time_t time_interval;
  } hosts6;

  bool silent;

  netstar_t *netstar;
};


extern netstar_hosts_t netstar_scanner_scanned_hosts4;
extern netstar_hosts_t netstar_scanner_scanned_hosts6;

extern int netstar_scanner_new(struct netstar_scanner *, netstar_t *);
extern void netstar_scanner_free(struct netstar_scanner *);

extern struct netstar_service *netstar_scanner_service(void);

#ifdef __cplusplus
}
#endif

#endif

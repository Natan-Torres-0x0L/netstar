#include "netstar-utils.h"

#include <collections/map/map.h>

#include <network/dns/dns.h>

#include <strings/strings.h>
#include <string.h>

// #include <regex.h>

#include <ctype.h>

#include <random/random.h>

#include <stdlib.h>
#include <stdio.h>

#include <stddef.h>
#include <stdint.h>


//
// netstar-utils::args macieee802
//

static bool
netstar_utils_args_macieee802_parse(network_macaddr_t *mac, const char *args) {
  return network_macaddr_parse(mac, args) != -1;
}

bool
netstar_utils_args_macieee802(network_macaddr_t *mac, const char *args) {
  return netstar_utils_args_macieee802_parse(mac, args);
}

//
// netstar-utils::args addrs
//

/*
bool
netstar_utils_args_ipaddr4_parse(network_ipaddr4_t *addr, const char *args) {
  return network_ipaddr4_parse(addr, args) != -1;
}

bool
netstar_utils_args_ipaddr6_parse(network_ipaddr6_t *addr, const char *args) {
  return network_ipaddr6_parse(addr, args) != -1;
}
*/

static inline void netstar_utils_args_addrs_free(char **);

static inline char **
netstar_utils_args_addrs_split(const char *args) {
  char **addrs = NULL, *formatted = NULL;

  if (!(formatted = string_replace(args, " ", "", -1, true)))
    goto _return;

  if ((addrs = string_split(formatted, "-", true)) && *addrs)
    goto _return;

  netstar_utils_args_addrs_free(addrs);
  addrs = NULL;

_return:
  free(formatted);
  return addrs;
}

static inline void
netstar_utils_args_addrs_free(char **addrs) {
  netstar_utils_strings_free(addrs);
}

//
// netstar-utils::args cidr/range
//

static bool
netstar_utils_args_cidr4_parse(network_ipaddr4_t *begin, network_ipaddr4_t *end, const char *args) {
  network_ipaddr4_t network = {0};
  uint8_t prefix;

  if (network_ipaddr4_cidr(args, &prefix, &network, NULL) == -1)
    return false;

  netstar_utils_ranges_ipaddr4(&network, prefix, begin, end);
  return true;
}

bool
netstar_utils_args_cidr4(network_ipaddr4_t *begin, network_ipaddr4_t *end, const char *args) {
  return netstar_utils_args_cidr4_parse(begin, end, args);
}

static bool
netstar_utils_args_range4_parse(network_ipaddr4_t *begin, network_ipaddr4_t *end, const char *args) {
  char **addrs = NULL;
  bool status = false;

  if (!(addrs = string_split(args, "-", true)) || !addrs[0] || !addrs[1])
    goto _return;

  if (network_ipaddr4_parse(begin, addrs[0]) == -1)
    goto _return;
  if (network_ipaddr4_parse(end, addrs[1]) == -1)
    goto _return;

  if (network_ipaddr4_compare(begin, end) == 1)
    goto _return;

  status = true;

_return:
  netstar_utils_args_addrs_free(addrs);
  return status;
}

bool
netstar_utils_args_range4(network_ipaddr4_t *begin, network_ipaddr4_t *end, const char *args) {
  return netstar_utils_args_range4_parse(begin, end, args);
}

static bool
netstar_utils_args_cidr6_parse(network_ipaddr6_t *begin, network_ipaddr6_t *end, const char *args) {
  network_ipaddr6_t network = {0};
  uint8_t prefix;

  if (network_ipaddr6_cidr(args, &prefix, &network, NULL) == -1)
    return false;

  netstar_utils_ranges_ipaddr6(&network, prefix, begin, end);
  return true;
}

bool
netstar_utils_args_cidr6(network_ipaddr6_t *begin, network_ipaddr6_t *end, const char *args) {
  return netstar_utils_args_cidr6_parse(begin, end, args);
}

static bool
netstar_utils_args_range6_parse(network_ipaddr6_t *begin, network_ipaddr6_t *end, const char *args) {
  char **addrs = NULL;
  bool status = false;

  if (!(addrs = string_split(args, "-", true)) || !addrs[0] || !addrs[1])
    goto _return;

  if (network_ipaddr6_parse(begin, addrs[0]) == -1)
    goto _return;
  if (network_ipaddr6_parse(end, addrs[1]) == -1)
    goto _return;

  if (network_ipaddr6_compare(begin, end) == 1)
    goto _return;

  status = true;

_return:
  netstar_utils_args_addrs_free(addrs);
  return status;
}

bool
netstar_utils_args_range6(network_ipaddr6_t *begin, network_ipaddr6_t *end, const char *args) {
  return netstar_utils_args_range6_parse(begin, end, args);
}

//
// netstar-utils::args hosts
//

#define NETSTAR_UTILS_ARGS_HOST4 0x01
#define NETSTAR_UTILS_ARGS_HOST6 0x02
#define NETSTAR_UTILS_ARGS_HOST  (NETSTAR_UTILS_ARGS_HOST4|NETSTAR_UTILS_ARGS_HOST6)

static bool
netstar_utils_args_host_parse(netstar_host_t *host, int inet, const char *args) {
  char **addrs = NULL, *mac = NULL, *addr = NULL;
  bool status = false;

  if (!(addrs = netstar_utils_args_addrs_split(args)))
    goto _return;

  if (addrs[0] && addrs[1]) {
    if ((host->inet = network_ipaddr_parse(&host->addr, addrs[0])) != -1 && network_macaddr_parse(&host->mac, addrs[1]) == 1)
      addr = addrs[0], mac = addrs[1];
    else if (network_macaddr_parse(&host->mac, addrs[0]) && (host->inet = network_ipaddr_parse(&host->addr, addrs[1])) != -1)
      mac = addrs[0], addr = addrs[1];
  } else {
    if ((host->inet = network_ipaddr_parse(&host->addr, addrs[0])) != -1)
      addr = addrs[0];
    else if (network_macaddr_parse(&host->mac, addrs[0]) == 1)
      mac = addrs[0];
  }

  if (!mac && !addr)
    goto _return;

  if (host->inet == NETWORK_IPADDR4 && !(NETSTAR_UTILS_ARGS_HOST4 & inet))
    goto _return;
  if (host->inet == NETWORK_IPADDR6 && !(NETSTAR_UTILS_ARGS_HOST6 & inet))
    goto _return;

  status = true;

_return:
  if (!status)
    memset(host, 0, sizeof(netstar_host_t));

  netstar_utils_args_addrs_free(addrs);
  return status;
}

bool
netstar_utils_args_host(netstar_host_t *host, const char *args) {
  return netstar_utils_args_host_parse(host, NETSTAR_UTILS_ARGS_HOST, args);
}

bool
netstar_utils_args_host4(netstar_host_t *host, const char *args) {
  return netstar_utils_args_host_parse(host, NETSTAR_UTILS_ARGS_HOST4, args);
}

bool
netstar_utils_args_host6(netstar_host_t *host, const char *args) {
  return netstar_utils_args_host_parse(host, NETSTAR_UTILS_ARGS_HOST6, args);
}

static inline char **
netstar_utils_args_hosts_split(const char *args) {
  char **hosts = NULL, *formatted;

  if (!(formatted = string_replace(args, " ", "", -1, true)))
    goto _return;

  hosts = string_split(formatted, ",", true);

_return:
  free(formatted);
  return hosts;
}

static inline void
netstar_utils_args_hosts_free(char **hosts) {
  netstar_utils_strings_free(hosts);
}

static int netstar_utils_filesystem_hosts_read(netstar_hosts_t, int, const char *);

bool
netstar_utils_args_hosts_parse(netstar_hosts_t hosts, int inet, const char *args) {
  char **hosts_addrs = NULL;
  size_t index;

  bool status = false;

  if (netstar_utils_filesystem_hosts_read(hosts, inet, args) != -1)
    return true;

  if (!(hosts_addrs = netstar_utils_args_hosts_split(args)))
    goto _return;

  for (index = 0; hosts_addrs[index]; index++) {
    struct netstar_host host = {0};

    if (!netstar_utils_args_host_parse(&host, inet, hosts_addrs[index]))
      goto _return;

    netstar_hosts_add(hosts, &host);
  }

  status = true;

_return:
  netstar_utils_args_hosts_free(hosts_addrs);
  return status && !netstar_hosts_empty(hosts);
}

bool
netstar_utils_args_hosts(netstar_hosts_t hosts, const char *args) {
  return netstar_utils_args_hosts_parse(hosts, NETSTAR_UTILS_ARGS_HOST, args);
}

bool
netstar_utils_args_hosts4(netstar_hosts_t hosts, const char *args) {
  return netstar_utils_args_hosts_parse(hosts, NETSTAR_UTILS_ARGS_HOST4, args);
}

bool
netstar_utils_args_hosts6(netstar_hosts_t hosts, const char *args) {
  return netstar_utils_args_hosts_parse(hosts, NETSTAR_UTILS_ARGS_HOST6, args);
}

//
// netstar-utils::args vendors
//

static inline char **
netstar_utils_args_vendor_oui_split(const char *vendor) {
  return string_split(vendor, "\t", true);
}

static inline void
netstar_utils_args_vendor_oui_free(char **oui) {
  netstar_utils_strings_free(oui);
}

static bool
netstar_utils_args_vendor_parse(struct netstar_vendor *vendor, const char *args) {
  const char *mac = NULL, *name = NULL;
  char **oui = NULL;

  bool status = false;

  if (!(oui = netstar_utils_args_vendor_oui_split(args)))
    goto _return;

  if (!(mac = oui[0]))
    goto _return;
  memcpy(vendor->mac, mac, string_length(mac));

  if (!(name = oui[1]))
    goto _return;
  memcpy(vendor->name, name, string_length(name));

  status = true;

_return:
  netstar_utils_args_vendor_oui_free(oui);
  return status;
}

//
// netstar-utils::args timeout
//

static bool
netstar_utils_args_time_parse(netstar_time_t *timeout, const char *args) {
  char measure[3] = {0};

  if (sscanf(args, "%d%2s", timeout, measure) != 2)
    return false;

  if (string_equals(measure, "s", true)) {
    *timeout = netstar_time_secstomillisecs(*timeout);
    return true;
  }
  if (string_equals(measure, "m", true)) {
    *timeout = netstar_time_minutestomillisecs(*timeout);
    return true;
  }
  if (string_equals(measure, "ms", true))
    return true;

  return false;
}

bool
netstar_utils_args_time(netstar_time_t *time, const char *args) {
  return netstar_utils_args_time_parse(time, args);
}

//
// netstar-utils::args number
//

static bool
netstar_utils_args_number_parse(uint64_t *count, const char *args) {
  long number;

  if ((number = netstar_utils_string_number(args)) < 0)
    return false;

  *count = (uint64_t)number;
  return true;
}

bool
netstar_utils_args_number(uint64_t *count, const char *args) {
  return netstar_utils_args_number_parse(count, args);
}

//
// netstar-utils::args packet data
//

static bool
netstar_utils_args_payload_format_parse(netstar_monitor_payload_format_t *payload_format, const char *args) {
  if (string_equals(args, "hexadecimal", true) || string_equals(args, "hex", true)) {
    *payload_format = NETSTAR_MONITOR_PAYLOAD_DATA_HEXADECIMAL;
    return true;
  }
  if (string_equals(args, "octal", true)) {
    *payload_format = NETSTAR_MONITOR_PAYLOAD_DATA_OCTAL;
    return true;
  }
  if (string_equals(args, "decimal", true)) {
    *payload_format = NETSTAR_MONITOR_PAYLOAD_DATA_DECIMAL;
    return true;
  }
  if (string_equals(args, "ascii", true)) {
    *payload_format = NETSTAR_MONITOR_PAYLOAD_DATA_ASCII;
    return true;
  }

  return false;
}

bool
netstar_utils_args_payloadformat(netstar_monitor_payload_format_t *payload_format, const char *args) {
  return netstar_utils_args_payload_format_parse(payload_format, args);
}

//
// netstar-utils::args redirect preroutes
//

static inline char **
netstar_utils_args_preroute_split(const char *preroute) {
  return string_fields(preroute);
}

static inline void
netstar_utils_args_preroute_free(char **preroute) {
  netstar_utils_strings_free(preroute);
}

static inline netstar_redirect_protocol_t
netstar_utils_args_preroute_protocol(const char *protocol) {
  if (string_equals(protocol, "tcp", false))
    return NETSTAR_REDIRECT_PROTOCOL_TCP;

  if (string_equals(protocol, "udp", false))
    return NETSTAR_REDIRECT_PROTOCOL_UDP;

  return NETSTAR_REDIRECT_PROTOCOL_UNKNOWN;
}

static bool
netstar_utils_args_preroute_parse(struct netstar_redirect_preroute *preroute, const char *args) {
  const char *protocol = NULL, *dport = NULL, *rport = NULL;
  char **fields = NULL;

  bool status = false;

  if (!(fields = netstar_utils_args_preroute_split(args)))
    goto _return;

  if (!(protocol = fields[0]) || !(preroute->protocol = netstar_utils_args_preroute_protocol(protocol)))
    goto _return;

  if (!(dport = fields[1]) || !(preroute->dport = (uint16_t)netstar_utils_string_number(dport)))
    goto _return;

  if (!(rport = fields[2]) || !(preroute->rport = (uint16_t)netstar_utils_string_number(rport)))
    goto _return;

  status = true;

_return:
  netstar_utils_args_preroute_free(fields);
  return status;
}

static char **
netstar_utils_args_preroutes_split(const char *args) {
  return string_split(args, ";", true);
}

static void
netstar_utils_args_preroutes_free(char **resources) {
  netstar_utils_strings_free(resources);
}

static bool
netstar_utils_args_preroutes_parse(netstar_redirect_preroutes_t preroutes, const char *args) {
  char **preroutes_rules = NULL;
  size_t index;

  bool status = false;

  if (netstar_utils_filesystem_preroutes(preroutes, args) != -1)
    return true;

  if (!(preroutes_rules = netstar_utils_args_preroutes_split(args)))
    goto _return;

  for (index = 0; preroutes_rules[index]; index++) {
    struct netstar_redirect_preroute preroute = {0};

    if (!netstar_utils_args_preroute_parse(&preroute, preroutes_rules[index]))
      goto _return;

    netstar_redirect_preroutes_add(preroutes, &preroute);
  }

  status = true;

_return:
  netstar_utils_args_preroutes_free(preroutes_rules);
  return status;
}

bool
netstar_utils_args_preroutes(netstar_redirect_preroutes_t preroutes, const char *args) {
  return netstar_utils_args_preroutes_parse(preroutes, args);
}

//
// netstar-utils::args filter
//

static bool
netstar_utils_args_filter_parse(netstar_filter_t *filter, netstar_t *netstar, const char *args) {
  char *expression = NULL;
  long start, end;

  bool status = false;

  if ((start = string_find(args, "[", true)) == -1)
    goto _return;
  if ((end = string_find(args, "]", true)) == -1)
    goto _return;

  if (!(expression = string_substr(args, start+1, end)))
    goto _return;

  if (netstar_filter_new(filter, netstar, expression) == -1)
    goto _return;

  status = true;

_return:
  free(expression);
  return status;
}

bool
netstar_utils_args_filter(netstar_filter_t *filter, netstar_t *netstar, const char *args) {
  return netstar_utils_args_filter_parse(filter, netstar, args);
}

//
// netstar-utils::args DNS resource record
//

static char **
netstar_utils_args_resource_split(const char *args) {
  return string_fields(args);
}

static void
netstar_utils_args_resource_free(char **resource) {
  netstar_utils_strings_free(resource);
}

static bool
netstar_utils_args_resource_parse(struct netstar_dns_spoofing_resource *resource, const char *args) {
  char *rname = NULL, *rtype = NULL, *rclass = NULL, *result = NULL;
  char **resource_record = NULL;

  bool status = false;

  if (!(resource_record = netstar_utils_args_resource_split(args)))
    goto _return;

  if (!(rname = resource_record[0]))
    goto _return;
  string_write(resource->name, rname, sizeof(resource->name));

  if (!(rtype = resource_record[1]))
    goto _return;
  resource->rtype = network_dns_type_parse(rtype);

  if (!(result = resource_record[2]))
    goto _return;
  string_write(resource->result, result, sizeof(resource->result));

  resource->rclass = NETWORK_DNS_CLASS_IN;
  if ((rclass = resource_record[3]))
    resource->rclass = network_dns_class_parse(rclass);

  status = true;

_return:
  netstar_utils_args_resource_free(resource_record);
  return status;
}

static char **
netstar_utils_args_resources_split(const char *args) {
  return string_split(args, ";", true);
}

static void
netstar_utils_args_resources_free(char **resources) {
  netstar_utils_strings_free(resources);
}

static bool
netstar_utils_args_resources_parse(netstar_dns_spoofing_resources_t resources, const char *args) {
  char **resource_records = NULL;
  size_t index;

  bool status = false;

  if (netstar_utils_filesystem_resources(resources, args) != -1)
    return true;

  if (!(resource_records = netstar_utils_args_resources_split(args)))
    goto _return;

  for (index = 0; resource_records[index]; index++) {
    struct netstar_dns_spoofing_resource resource = {0};

    if (!netstar_utils_args_resource_parse(&resource, resource_records[index]))
      goto _return;

    netstar_dns_spoofing_resources_add(resources, &resource);
  }

  status = true;

_return:
  netstar_utils_args_resources_free(resource_records);
  return status;
}

bool
netstar_utils_args_resources(netstar_dns_spoofing_resources_t resources, const char *args) {
  return netstar_utils_args_resources_parse(resources, args);
}

//
// netstar-utils::stealth
//

network_macaddr_t *
netstar_utils_stealth_macieee802(const char *stealth_mac) {
  static thread_local network_macaddr_t mac = {0};

  if (!stealth_mac)
    return netstar_utils_random_macieee802();

  network_macaddr_parse(&mac, stealth_mac);

  return &mac;
}

//
// netstar-utils::random
//

network_macaddr_t *
netstar_utils_random_macieee802(void) {
  static thread_local network_macaddr_t mac = {0};
  uint8_t byte;

  for (byte = 0; byte < NETWORK_MACADDR_SIZE; byte++)
    mac.u8[byte] = random_uint8();

#if defined _WIN16 || defined _WIN32 || defined _WIN64 || defined __WIN32__ || defined __TOS_WIN__ || defined __WINDOWS__
  mac.u8[0] &= 0xFC; // I/G bit = 0
  mac.u8[0] |= 0x02; // U/L bit = 1
#endif

  return &mac;
}

network_ipaddr4_t *
netstar_utils_random_ipaddr4(const network_ipaddr4_t *network, uint8_t prefix) {
  network_ipaddr4_t netmask = { .u32 = ((!prefix) ? 0 : htonl(~((1U << (32-prefix))-1))) };
  network_ipaddr4_t broadcast = { .u32 = (network->u32 & netmask.u32) | (~netmask.u32) };

  uint32_t network_range = ntohl(broadcast.u32)-ntohl(network->u32);
  static thread_local network_ipaddr4_t addr = {0};

  addr.u32 = htonl(ntohl(network->u32)+(random_uint32() & network_range));

  return &addr;
}

// network_ipaddr6_t *
// netstar_utils_random_ipaddr6(const network_ipaddr6_t *network, uint8_t prefix) {
// 
// }

//
// netstar-utils::ranges
//

void
netstar_utils_ranges_ipaddr4(const network_ipaddr4_t *network, uint8_t prefix, network_ipaddr4_t *begin, network_ipaddr4_t *end) {
  if (prefix <= 32) {
    network_ipaddr4_t netmask = { .u32 = ((!prefix) ? 0 : htonl(~((1U << (32-prefix))-1))) };

    begin->u32 = network->u32;
    end->u32 = (network->u32 & netmask.u32) | (~netmask.u32);
  }
}

void
netstar_utils_ranges_ipaddr6(const network_ipaddr6_t *network, uint8_t prefix, network_ipaddr6_t *begin, network_ipaddr6_t *end) {
  uint8_t byte, full_bytes, remaining_bits;

  if (prefix == 128) {
    memcpy(begin->u8, network->u8, NETWORK_IPADDR6_SIZE);
    memcpy(end->u8, network->u8, NETWORK_IPADDR6_SIZE);

    return;
  }

  full_bytes = prefix / 8;
  remaining_bits = prefix % 8;

  memcpy(begin->u8, network->u8, NETWORK_IPADDR6_SIZE);
  memcpy(end->u8, network->u8, NETWORK_IPADDR6_SIZE);

  for (byte = full_bytes + (remaining_bits ? 1 : 0); byte < NETWORK_IPADDR6_SIZE; byte++) {
    begin->u8[byte] = 0x00;
    end->u8[byte] = 0xFF;
  }

  if (remaining_bits) {
    uint8_t mask = (uint8_t)(0xFF << (8 - remaining_bits));

    begin->u8[full_bytes] &= mask;
    end->u8[full_bytes]   |= (uint8_t)(~mask);
  }
}

#ifdef NETSTAR_EXTENDED
//
// netstar-utils::regex
//

bool
netstar_utils_regex_match(const char *string, const char *pattern, char *string_capture, size_t string_capture_length) {
  int start = -1, end = -1;
  regmatch_t matches[2];
  regex_t regex = {0};

  int status = -1;

  if (regcomp(&regex, pattern, REG_EXTENDED|REG_ICASE) != 0)
    goto _return;

  if ((status = regexec(&regex, string, 0, NULL, 0)) != 0)
    goto _return;

  start = matches[1].rm_so;
  end = matches[1].rm_eo;

  if (string_capture && start >= 0 && end > start && (size_t)(end-start) < string_capture_length)
    memcpy(string_capture, string+start, (size_t)end-start);

_return:
  regfree(&regex);

  return status == 0;
}
#endif

//
// netstar-utils::strings
//

/*
void
netstar_utils_string_vformat(buffer_t *buffer, const char *restrict format, va_args args) {
  size_t capacity, resize = buffer_length(buffer);
  char *ptr = NULL;

  va_list format_args;
  int length = -1;

  format_args = args;
  if ((length = vsnprintf(NULL, 0, format, format_args)) == -1 || (resize+length > buffer_capacity(buffer) && buffer_reserve(buffer, (resize+length)*2) == -1))
    return;
  ptr = (char *)(buffer_ptr(buffer)+resize);
  capacity = buffer_capacity(buffer);

  format_args = args;
  if (vsnprintf(ptr, capacity, format, format_args) == -1)
    return;
  resize += length;
  buffer_resize(buffer, resize);
}
*/

static int
netstar_utils_string_vformat_ensure_space(buffer_t *buffer, size_t extra) {
  size_t required, capacity;

  if ((required = buffer_length(buffer)+extra) <= buffer_capacity(buffer))
    return 1;

  capacity = (buffer_capacity(buffer)+required)*2;

  return buffer_reserve(buffer, capacity);
}

int
netstar_utils_string_vformat(buffer_t *buffer, const char *restrict format, va_list args) {
  va_list format_args;

  int written = -1, needed = -1;
  size_t offset;

  char *string = NULL;

  va_copy(format_args, args);
  if ((needed = vsnprintf(NULL, 0, format, format_args)) == -1)
    return -1;

  va_end(format_args);

  if (netstar_utils_string_vformat_ensure_space(buffer, (size_t)needed) == -1)
    return -1;

  offset = buffer_length(buffer);
  string = (char *)buffer_ptr(buffer)+offset;

  va_copy(format_args, args);
  written = vsnprintf(string, buffer_capacity(buffer), format, format_args);
  va_end(format_args);

  buffer_resize(buffer, offset+written);
  return written;
}

int
netstar_utils_string_format(buffer_t *buffer, const char *restrict format, ...) {
  va_list args;
  int written = -1;

  va_start(args, format);
  written = netstar_utils_string_vformat(buffer, format, args);
  va_end(args);

  return written;
}

size_t
netstar_utils_string_readline(const char *source, size_t source_length, char *buffer, size_t buffer_length) {
  size_t read = 0;

  while (source_length > 0 && buffer_length > 0) {
    if (source_length >= 2 && *source == '\r' && *(source+1) == '\n') {
      read += 2;
      break;
    } else if (*source == '\n') {
      read += 1;
      break;
    }

    *buffer++ = *source++;

    source_length--, buffer_length--;
    read++;
  }

  return read;
}

static uint8_t
netstar_utils_string_number_base(const char *string) {
  uint8_t number_base = 10;

  if (*string == '0') {
    int prefix = tolower(*(string+1));

    switch (prefix) {
      case 'b': number_base = 2; break;
      case 'o': number_base = 8; break;
      case 'x': number_base = 16; break;
    }
  }

  return number_base;
}

static inline bool
netstar_utils_string_number_is_negative(const char **string) {
  if (*(*string) == '-' && *(*string++))
    return true;

  if (*(*string) == '+')
    (void)*(string++);

  return false;
}

static inline long
netstar_utils_string_number_digit(int symbol, int number_base) {
  if (symbol >= '0' && symbol <= '9')
    return symbol-'0';
  
  if (number_base == 16) {
    if (symbol >= 'a' && symbol <= 'f')
      return symbol-'a'+10;
    if (symbol >= 'A' && symbol <= 'F')
      return symbol-'A'+10;
  }

  return -1;
}

long
netstar_utils_string_number(const char *string) {
  uint8_t number_base = netstar_utils_string_number_base(string);
  bool negative = netstar_utils_string_number_is_negative(&string);  
  long number = 0;

  long digit;

  while (*string && (digit = netstar_utils_string_number_digit(*string, number_base)) >= 0) {
    number = (number*number_base)+digit;
    string++;
  }

  number = (negative ? number*-1 : number);

  return number;
}

void
netstar_utils_strings_free(char **strings) {
  if (strings) {
    size_t index;

    for (index = 0; strings[index]; index++)
      free(strings[index]);

    free(strings);
  }
}

//
// netstar-utils::filesystem
//

static bool netstar_utils_filesystem_initialized;

static map_t *netstar_utils_filesystem_files;


static int
netstar_utils_filesystem_files_compare(const void *path1, size_t path1_length, const void *path2, size_t path2_length) {
  return string_compare((const char *)path1, (const char *)path2, true);
}

__attribute__((__constructor__))
static inline void
netstar_utils_filesystem_initialize(void) {
  if (netstar_utils_filesystem_initialized)
    return;

  if (!(netstar_utils_filesystem_files = map_new(netstar_utils_filesystem_files_compare, free, NULL)))
    return;

  netstar_utils_filesystem_initialized = true;
}

__attribute__((__destructor__))
static inline void
netstar_utils_filesystem_deinitialize(void) {
  if (!netstar_utils_filesystem_initialized)
    return;

  map_free(netstar_utils_filesystem_files);

  netstar_utils_filesystem_initialized = false;
}

static inline FILE *
netstar_utils_filesystem_open(const char *filename, const char *mode) {
  return fopen(filename, mode);
}

static inline void
netstar_utils_filesystem_close(FILE *file) {
  if (file) {
    fclose(file);
  }
}

static inline FILE *
netstar_utils_filesystem_open_once(const char *filename, const char *mode) {
  FILE *file = NULL;

  if (map_get(netstar_utils_filesystem_files, filename, string_length(filename)))
    return NULL;

  if (!(file = netstar_utils_filesystem_open(filename, mode)))
    return NULL;

  map_insert(netstar_utils_filesystem_files, map_clkey(filename, string_length(filename)+1), map_rvalue(file, sizeof(FILE *)));

  return file;
}

static inline void
netstar_utils_filesystem_close_once(const char *filename) {
  FILE *file = NULL;

  if (!(file = (FILE *)map_get(netstar_utils_filesystem_files, filename, string_length(filename))))
    return;

  map_remove(netstar_utils_filesystem_files, filename, string_length(filename));

  netstar_utils_filesystem_close(file);
}

#define NETSTAR_UTILS_FILESYSTEM_VENDORS_LINE_LENGTH    NETWORK_MACADDR_STRLENGTH+NETSTAR_VENDOR_STRLENGTH+0x10

static int
netstar_utils_filesystem_vendors_read(netstar_vendors_t vendors, const char *filename) {
  char vendor_line[NETSTAR_UTILS_FILESYSTEM_VENDORS_LINE_LENGTH] = {0};
  FILE *vendors_file = NULL;

  if (!(vendors_file = netstar_utils_filesystem_open(filename, "r")))
    return -1;

  for (;;) {
    struct netstar_vendor vendor = {0};

    memset(vendor_line, 0, sizeof(vendor_line));

    if (!fgets(vendor_line, sizeof(vendor_line), vendors_file))
      break;
    if (string_chomp(vendor_line) && vendor_line[0] == '#')
      continue;

    if (!netstar_utils_args_vendor_parse(&vendor, vendor_line))
      continue;

    netstar_vendors_add(vendors, &vendor);
  }

  netstar_utils_filesystem_close(vendors_file);
  return 1;
}

int
netstar_utils_filesystem_vendors(netstar_vendors_t vendors, const char *filename) {
  return netstar_utils_filesystem_vendors_read(vendors, filename);
}

#define NETSTAR_UTILS_FILESYSTEM_HOSTS_LINE_LENGTH NETWORK_IPADDR6_STRLENGTH*4

static int
netstar_utils_filesystem_hosts_read(netstar_hosts_t hosts, int inet, const char *filename) {
  char hosts_line[NETSTAR_UTILS_FILESYSTEM_HOSTS_LINE_LENGTH] = {0};
  FILE *hosts_file = NULL;

  if (!(hosts_file = netstar_utils_filesystem_open_once(filename, "r")))
    return -1;

  for (;;) {
    memset(hosts_line, 0, sizeof(hosts_line));

    if (!fgets(hosts_line, sizeof(hosts_line), hosts_file))
      break;
    if (string_chomp(hosts_line) && hosts_line[0] == '#')
      continue;

    netstar_utils_args_hosts_parse(hosts, inet, hosts_line);
  }

  netstar_utils_filesystem_close_once(filename);
  return 1;
}

int
netstar_utils_filesystem_hosts(netstar_hosts_t hosts, const char *filename) {
  return netstar_utils_filesystem_hosts_read(hosts, NETSTAR_UTILS_ARGS_HOST, filename);
}

#define NETSTAR_UTILS_FILESYSTEM_PREROUTES_LINE_LENGTH 1024

static int
netstar_utils_filesystem_preroutes_read(netstar_redirect_preroutes_t preroutes, const char *filename) {
  char preroutes_line[NETSTAR_UTILS_FILESYSTEM_PREROUTES_LINE_LENGTH] = {0};
  FILE *preroutes_file = NULL;

  if (!(preroutes_file = netstar_utils_filesystem_open_once(filename, "r")))
    return -1;

  for (;;) {
    memset(preroutes_line, 0, sizeof(preroutes_line));

    if (!fgets(preroutes_line, sizeof(preroutes_line), preroutes_file))
      break;
    if (string_chomp(preroutes_line) && preroutes_line[0] == '#')
      continue;

    netstar_utils_args_preroutes_parse(preroutes, preroutes_line);
  }

  netstar_utils_filesystem_close_once(filename);
  return 1;
}

int
netstar_utils_filesystem_preroutes(netstar_redirect_preroutes_t preroutes, const char *filename) {
  return netstar_utils_filesystem_preroutes_read(preroutes, filename);
}

#define NETSTAR_UTILS_FILESYSTEM_RESOURCES_LINE_LENGTH 1024

static int
netstar_utils_filesystem_resources_read(netstar_dns_spoofing_resources_t resources, const char *filename) {
  char resource_line[NETSTAR_UTILS_FILESYSTEM_RESOURCES_LINE_LENGTH] = {0};
  FILE *resources_file = NULL;

  if (!(resources_file = netstar_utils_filesystem_open_once(filename, "r")))
    return -1;

  for (;;) {
    memset(resource_line, 0, sizeof(resource_line));

    if (!fgets(resource_line, sizeof(resource_line), resources_file))
      break;
    if (string_chomp(resource_line) && resource_line[0] == '#')
      continue;

    netstar_utils_args_resources(resources, resource_line);
  }

  netstar_utils_filesystem_close_once(filename);
  return 1;
}

int
netstar_utils_filesystem_resources(netstar_dns_spoofing_resources_t resources, const char *filename) {
  return netstar_utils_filesystem_resources_read(resources, filename);
}

buffer_t *
netstar_utils_filesystem_read(const char *filename, const char *mode) {
  buffer_t *buffer = NULL;

  FILE *file = NULL;
  long file_size;

  if (!(file = netstar_utils_filesystem_open(filename, mode)) || fseek(file, 0, SEEK_END) == -1)
    goto _return;

  if ((file_size = ftell(file)) == -1 || fseek(file, 0, SEEK_SET) == -1)
    goto _return;

  if (!(buffer = buffer_make((size_t)file_size, (size_t)file_size)))
    goto _return;

  if (fread(buffer_ptr(buffer), sizeof(char), (size_t)file_size, file) == -1)
    goto _return;

  fclose(file);

  return buffer;

_return:
  buffer_free(buffer);
  netstar_utils_filesystem_close(file);

  return NULL;
}

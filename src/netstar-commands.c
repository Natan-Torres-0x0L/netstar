#include "netstar-commands.h"

#include <netstar-ndp-spoofing.h>
#include <netstar-arp-spoofing.h>

#include <netstar-dns-spoofing.h>
#include <netstar-http-server.h>

#include <netstar-redirect.h>
#include <netstar-stealth.h>

#include <netstar-monitor.h>
#include <netstar-scanner.h>

#include <netstar-services.h>

#include <netstar-utils.h>

#include <console/arguments/arguments.h>
#include <strings/strings.h>

#include <system/system.h>


static struct console_args_command netstar_arp_broadcast_spoofing_commands[] = {
  { .name = "netstar:arp:broadcast-spoofing:spoof-steady-interval", .flags = "--spoof-steady-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:broadcast-spoofing:spoof-burst-interval", .flags = "--spoof-burst-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:broadcast-spoofing:spoof-burst-count", .flags = "--spoof-burst-count", .sensitive = true, .required = false, .required_values = 1, },
};
static struct console_args_command netstar_arp_broadcast_spoofing_command = {
  .name = "netstar:arp:broadcast-spoofing", .flags = "--broadcast-spoofing", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_arp_broadcast_spoofing_commands),
};

static struct console_args_command netstar_arp_network_spoofing_commands[] = {
  { .name = "netstar:arp:network-spoofing:protected-hosts", .flags = "--protected-hosts", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:network-spoofing:redirection-host", .flags = "--redirection-host", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:network-spoofing:bidirectional", .flags = "--bidirectional", .sensitive = true, .required = false, },
  { .name = "netstar:arp:network-spoofing:network-scan-interval", .flags = "--network-scan-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:network-spoofing:spoof-steady-interval", .flags = "--spoof-steady-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:network-spoofing:spoof-burst-interval", .flags = "--spoof-burst-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:network-spoofing:spoof-burst-count", .flags = "--spoof-burst-count", .sensitive = true, .required = false, .required_values = 1, },
};
static struct console_args_command netstar_arp_network_spoofing_command = {
  .name = "netstar:arp:network-spoofing", .flags = "--network-spoofing", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_arp_network_spoofing_commands),
};

static struct console_args_command netstar_arp_spoofing_commands[] = {
  { .name = "netstar:arp:spoofing:redirection-host", .flags = "--redirection-host", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:spoofing:bidirectional", .flags = "--bidirectional", .sensitive = true, .required = false, },
  { .name = "netstar:arp:spoofing:spoof-steady-interval", .flags = "--spoof-steady-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:spoofing:spoof-burst-interval", .flags = "--spoof-burst-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:arp:spoofing:spoof-burst-count", .flags = "--spoof-burst-count", .sensitive = true, .required = false, .required_values = 1, },
};
static struct console_args_command netstar_arp_spoofing_command = {
  .name = "netstar:arp:spoofing", .flags = "--spoofing", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_arp_spoofing_commands),
};

static struct console_args_command *netstar_arp_commands[] = {
  &netstar_arp_broadcast_spoofing_command,
  &netstar_arp_network_spoofing_command,
  &netstar_arp_spoofing_command
};
static struct console_args_command netstar_arp_command = {
  .name = "netstar:arp", .flags = "arp", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_reference(netstar_arp_commands),
};

static struct console_args_command netstar_ndp_network_spoofing_commands[] = {
  { .name = "netstar:ndp:network-spoofing:protected-hosts", .flags = "--protected-hosts", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:ndp:network-spoofing:redirection-host", .flags = "--redirection-host", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:ndp:network-spoofing:bidirectional", .flags = "--bidirectional", .sensitive = true, .required = false, },
  { .name = "netstar:ndp:network-spoofing:network-scan-interval", .flags = "--network-scan-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:ndp:network-spoofing:spoof-steady-interval", .flags = "--spoof-steady-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:ndp:network-spoofing:spoof-burst-interval", .flags = "--spoof-burst-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:ndp:network-spoofing:spoof-burst-count", .flags = "--spoof-burst-count", .sensitive = true, .required = false, .required_values = 1, },
};
static struct console_args_command netstar_ndp_network_spoofing_command = {
  .name = "netstar:ndp:network-spoofing", .flags = "--network-spoofing", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_ndp_network_spoofing_commands),
};

static struct console_args_command netstar_ndp_spoofing_commands[] = {
  { .name = "netstar:ndp:spoofing:bidirectional", .flags = "--bidirectional", .sensitive = true, .required = false, },
  { .name = "netstar:ndp:spoofing:spoof-steady-interval", .flags = "--spoof-steady-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:ndp:spoofing:spoof-burst-interval", .flags = "--spoof-burst-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:ndp:spoofing:spoof-burst-count", .flags = "--spoof-burst-count", .sensitive = true, .required = false, .required_values = 1, },
};
static struct console_args_command netstar_ndp_spoofing_command = {
  .name = "netstar:ndp:spoofing", .flags = "--spoofing", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_ndp_spoofing_commands),
};

static struct console_args_command *netstar_ndp_commands[] = {
  &netstar_ndp_network_spoofing_command,
  &netstar_ndp_spoofing_command
};
static struct console_args_command netstar_ndp_command = {
  .name = "netstar:ndp", .flags = "ndp", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_reference(netstar_ndp_commands),
};

static struct console_args_command netstar_dns_spoofing_commands[] = {
  { .name = "netstar:dns:spoofing:target-hosts", .flags = "--target-hosts", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:dns:spoofing:protected-hosts", .flags = "--protected-hosts", .sensitive = true, .required = false, .required_values = 1, },
};
static struct console_args_command netstar_dns_spoofing_command = {
  .name = "netstar:dns:spoofing", .flags = "--spoofing", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_dns_spoofing_commands),
};

static struct console_args_command *netstar_dns_commands[] = {
  &netstar_dns_spoofing_command,
};
static struct console_args_command netstar_dns_command = {
  .name = "netstar:dns", .flags = "dns", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_reference(netstar_dns_commands),
};

static struct console_args_command netstar_http_server_command = {
  .name = "netstar:http:server", .flags = "--server", .sensitive = true, .required = false, .required_values = 0,
};
static struct console_args_command *netstar_http_commands[] = {
  &netstar_http_server_command,
};
static struct console_args_command netstar_http_command = {
  .name = "netstar:http", .flags = "http", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_reference(netstar_http_commands),
};

static struct console_args_command netstar_redirect_commands[] = {
  { .name = "netstar:redirect:prerouting", .flags = "--prerouting", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:redirect:preexcluded-hosts", .flags = "--preexclude-hosts", .sensitive = true, .required = false, .required_values = 1, },
};
static struct console_args_command netstar_redirect_command = {
  .name = "netstar:redirect", .flags = "redirect", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_redirect_commands),
};

static struct console_args_command netstar_monitor_commands[] = {
  { .name = "netstar:monitor:link-layer", .flags = "--link-layer", .sensitive = true, .required = false, .required_values = 0, },
  { .name = "netstar:monitor:network-layer", .flags = "--network-layer", .sensitive = true, .required = false, .required_values = 0, },
  { .name = "netstar:monitor:transport-layer", .flags = "--transport-layer", .sensitive = true, .required = false, .required_values = 0, },
  { .name = "netstar:monitor:payload", .flags = "--payload", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:monitor:filter", .flags = "--filter", .sensitive = true, .required = false, .required_values = 1, },
};
static struct console_args_command netstar_monitor_command = {
  .name = "netstar:monitor", .flags = "monitor", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_monitor_commands),
};

static struct console_args_command netstar_scanner_commands[] = {
  { .name = "netstar:scanner:stealth-scan", .flags = "--stealth-scan", .sensitive = true, .required = false, .required_values = 0, },
  { .name = "netstar:scanner:scan-hosts4-cidr", .flags = "--scan-hosts4-cidr", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:scanner:scan-hosts4-range", .flags = "--scan-hosts4-range", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:scanner:scan-hosts4-interval", .flags = "--scan-hosts4-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:scanner:scan-hosts4-only", .flags = "--scan-hosts4-only", .sensitive = true, .required = false, .required_values = 0, },
  { .name = "netstar:scanner:scan-hosts6-cidr", .flags = "--scan-hosts6-cidr", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:scanner:scan-hosts6-range", .flags = "--scan-hosts6-range", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:scanner:scan-hosts6-interval", .flags = "--scan-hosts6-interval", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:scanner:scan-hosts6-only", .flags = "--scan-hosts6-only", .sensitive = true, .required = false, .required_values = 0, },
  { .name = "netstar:scanner:preexcluded-hosts", .flags = "--preexclude-hosts", .sensitive = true, .required = false, .required_values = 1, },
  { .name = "netstar:scanner:silent", .flags = "--silent", .sensitive = true, .required = false, .required_values = 0, },
};
static struct console_args_command netstar_scanner_command = {
  .name = "netstar:scanner", .flags = "scanner", .sensitive = true, .required = false, .required_values = -1,
  .subcommands = console_args_subcommands_array(netstar_scanner_commands),
};

static struct console_args_command netstar_forward_command = {
  .name = "netstar:forward", .flags = "--forward", .sensitive = true, .required = false, .required_values = 0,
};
static struct console_args_command netstar_stealth_command = {
  .name = "netstar:stealth", .flags = "--stealth", .sensitive = true, .required = false, .required_values = -1,
};
static struct console_args_command netstar_managed_iface = {
  .name = "netstar:managed-interface", .flags = "-i|--iface", .sensitive = true, .required = false, .required_values = 1,
};


static inline void
netstar_command_version(struct console_args_command *command) {
  static char architecture[sizeof(SYSTEM_TARGET_ARCHITECTURE)+1] = SYSTEM_TARGET_ARCHITECTURE;
  static char system[sizeof(SYSTEM_TARGET_NAME)+1] = SYSTEM_TARGET_NAME;

  netstar_printf("Netstar version v" NETSTAR_VERSION " %s/%s\r\n\r\n", string_tolower(system), string_tolower(architecture));

  netstar_exit(NETSTAR_EXIT_SUCCESS);
}

struct console_args_command netstar_version_command = {
  .name = "netstar:version", .flags = "--version|version", .sensitive = true, .required = false, .required_values = 1,
  .routine = netstar_command_version,
};

static inline void
netstar_command_about(struct console_args_command *command) {
  netstar_printf("Netstar (Network Stealth Traffic Analyzer and Redirector) is a powerful suite for local network "
                 "MITM attacks. It supports ARP/NDP spoofing, DNS poisoning, stealth MAC spoofing, IPv4/IPv6 host "
                 "scanning, real-time traffic analysis, content filtering, and traffic redirection for deep network "
                 "exploration.\r\n\r\n");

  netstar_exit(NETSTAR_EXIT_SUCCESS);
}

struct console_args_command netstar_about_command = {
  .name = "netstar:about", .flags = "--about|about", .sensitive = true, .required = false, .required_values = 1,
  .routine = netstar_command_about,
};


static inline void
netstar_command_arp_command_help(struct console_args_command *command) {
  if (string_equals(command->values[1], "--broadcast-spoofing", true) || string_equals(command->values[1], "broadcast-spoofing", true)) {
    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar arp --broadcast-spoofing [spoofed-hosts] [arguments]\r\n"
                   "\r\n"
                   "Arguments:\r\n"
                   "  --spoof-burst-interval  time interval in microseconds between packets during storm-phase attacks (max speed)\r\n"
                   "  --spoof-burst-count     number of high-speed spoofing attempts during storm phase\r\n"
                   "\r\n"
                   "  --spoof-steady-interval stable time interval in milliseconds for periodic spoofing after initial infection\r\n"
                   "\r\n"
    );
  } else if (string_equals(command->values[1], "--network-spoofing", true) || string_equals(command->values[1], "network-spoofing", true)) {
    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar arp --network-spoofing [spoofed-hosts] [arguments]\r\n"
                   "\r\n"
                   "Arguments:\r\n"
                   "\r\n"
                   "  --network-scan-interval time interval to wait for hosts to be discovered on the network\r\n"
                   "\r\n"
                   "  --spoof-burst-interval  time interval in minutes/seconds/microseconds between packets during shockwave-phase attacks\r\n"
                   "  --spoof-burst-count     number of high-speed spoofing attempts during storm phase\r\n"
                   "\r\n"
                   "  --spoof-steady-interval stable time interval in minutes/seconds/microseconds for periodic spoofing\r\n"
                   "\r\n"
                   "  --bidirectional         bidirectional ARP spoofing between victims and targets\r\n"
                   "\r\n"
                   "  --redirection-host      redirect spoofed traffic to an alternate IPv4 host for load balancing and stealth\r\n"
                   "\r\n"
                   "  --protected-hosts       list of IPv4 hosts to be protected from ARP spoofing attacks\r\n"
                   "\r\n"
    );
  } else if (string_equals(command->values[1], "--spoofing", true) || string_equals(command->values[1], "spoofing", true)) {
    netstar_printf("Usage:\r\n\r\n"
                   "  netstar arp --spoofing [spoofed-hosts] [target-hosts] [arguments]\r\n"
                   "\r\n"
                   "Arguments:\r\n"
                   "\r\n"
                   "  --spoof-burst-interval  time interval in minutes/seconds/microseconds between packets during shockwave-phase attacks\r\n"
                   "  --spoof-burst-count     number of high-speed spoofing attempts during storm phase\r\n"
                   "\r\n"
                   "  --spoof-steady-interval stable time interval in minutes/seconds/microseconds for periodic spoofing\r\n"
                   "\r\n"
                   "  --bidirectional         bidirectional ARP spoofing between victims and targets\r\n"
                   "\r\n"
                   "  --redirection-host      redirect spoofed traffic to an alternate IPv4 host for load balancing and stealth\r\n"
                   "\r\n"
                   "  --protected-hosts       list of IPv4 hosts to be protected from ARP spoofing attacks\r\n"
                   "\r\n"
    );
  } else {
    netstar_printf("Unknown help arp command \"%s\". Use \"netstar help arp\".\r\n", command->values[1]);
  }
}

static inline void
netstar_command_ndp_command_help(struct console_args_command *command) {
  if (string_equals(command->values[1], "--network-spoofing", true) || string_equals(command->values[1], "network-spoofing", true)) {
    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar ndp --network-spoofing [spoofed-hosts] [arguments]\r\n"
                   "\r\n"
                   "Arguments:\r\n"
                   "\r\n"
                   "  --network-scan-interval time interval to wait for hosts to be discovered on the network\r\n"
                   "\r\n"
                   "  --spoof-burst-interval  time interval in minutes/seconds/microseconds between packets during shockwave-phase attacks\r\n"
                   "  --spoof-burst-count     number of high-speed spoofing attempts during storm phase\r\n"
                   "\r\n"
                   "  --spoof-steady-interval stable time interval in minutes/seconds/microseconds for periodic spoofing\r\n"
                   "\r\n"
                   "  --bidirectional         bidirectional NDP spoofing between victims and targets\r\n"
                   "\r\n"
                   "  --redirection-host      redirect spoofed traffic to an alternate IPv6 host for load balancing and stealth\r\n"
                   "\r\n"
                   "  --protected-hosts       list of IPv6 hosts to be protected from ndp spoofing attacks\r\n"
                   "\r\n"
    );
  } else if (string_equals(command->values[1], "--spoofing", true) || string_equals(command->values[1], "spoofing", true)) {
    netstar_printf("Usage:\r\n\r\n"
                   "  netstar ndp --spoofing [spoofed-hosts] [target-hosts] [arguments]\r\n"
                   "\r\n"
                   "Arguments:\r\n"
                   "\r\n"
                   "  --spoof-burst-interval  time interval in minutes/seconds/microseconds between packets during shockwave-phase attacks\r\n"
                   "  --spoof-burst-count     number of high-speed spoofing attempts during storm phase\r\n"
                   "\r\n"
                   "  --spoof-steady-interval stable time interval in minutes/seconds/microseconds for periodic spoofing\r\n"
                   "\r\n"
                   "  --bidirectional         bidirectional NDP spoofing between victims and targets\r\n"
                   "\r\n"
                   "  --redirection-host      redirect spoofed traffic to an alternate IPv6 host for load balancing and stealth\r\n"
                   "\r\n"
                   "  --protected-hosts       list of IPv6 hosts to be protected from ndp spoofing attacks\r\n"
                   "\r\n"
    );
  } else {
    netstar_printf("Unknown help ndp command \"%s\". Use \"netstar help ndp\".\r\n", command->values[1]);
  }
}

static inline void
netstar_command_dns_command_help(struct console_args_command *command) {
  if (string_equals(command->values[1], "--network-spoofing", true) || string_equals(command->values[1], "network-spoofing", true)) {
    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar dns --spoofing [resource-records] [arguments]\r\n"
                   "\r\n"
                   "Arguments:\r\n"
                   "\r\n"
                   "  --protected-hosts  list of IPv4/IPv6 hosts to be protected from dns spoofing attacks\r\n"
                   "  --target-hosts     specifies the IPv4/IPv6 hosts that will be targeted by DNS spoofing\r\n"
                   "\r\n");
  } else {
    netstar_printf("Unknown help dns command \"%s\". Use \"netstar help dns\".\r\n", command->values[1]);
  }
}

static inline void
netstar_command_redirect_command_help(struct console_args_command *command) {
  if (string_equals(command->values[1], "--prerouting", true) || string_equals(command->values[1], "prerouting", true)) {
    netstar_printf("Usage:\r\n\r\n"
                   "  netstar redirect --prerouting [redirection-rules]\r\n"
                   "\r\n");
  } else {
    netstar_printf("Unknown help redirect command \"%s\". Use \"netstar help redirect\".\r\n", command->values[1]);
  }
}

static inline void
netstar_command_help_topic(struct console_args_command *command) {
  if (string_equals(command->value, "arp", true)) {
    if (command->values_count > 1) {
      netstar_command_arp_command_help(command);
      netstar_exit(NETSTAR_EXIT_SUCCESS);
    }

    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar arp <command> [arguments]\r\n"
                   "\r\n"
                   "Commands:\r\n"
                   "\r\n"
                   "  netstar arp --broadcast-spoofing [spoofed-hosts] [arguments]\r\n"
                   "\r\n"
                   "  netstar arp --network-spoofing [spoofed-hosts] [arguments]\r\n"
                   "\r\n"
                   "  netstar arp --spoofing [spoofed-hosts] [target-hosts] [arguments]\r\n"
                   "\r\n");

    netstar_printf("Use \"netstar help arp <command>\" for more information about that command.\r\n\r\n");
  } else if (string_equals(command->value, "ndp", true)) {
    if (command->values_count > 1) {
      netstar_command_ndp_command_help(command);
      netstar_exit(NETSTAR_EXIT_SUCCESS);
    }

    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar ndp <command> [arguments]\r\n"
                   "\r\n"
                   "Commands:\r\n"
                   "\r\n"
                   "  netstar ndp --network-spoofing [spoofed-hosts] [arguments]\r\n"
                   "\r\n"
                   "  netstar ndp --spoofing [spoofed-hosts] [target-hosts] [arguments]\r\n"
                   "\r\n");
  } else if (string_equals(command->value, "dns", true)) {
    if (command->values_count > 1) {
      netstar_command_dns_command_help(command);
      netstar_exit(NETSTAR_EXIT_SUCCESS);
    }

    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar dns <command> [arguments]\r\n"
                   "\r\n"
                   "Commands:\r\n"
                   "\r\n"
                   "  netstar dns --spoofing [resource-records]\r\n"
                   "\r\n");
  } else if (string_equals(command->value, "http", true)) {
    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar http <command> [arguments]\r\n"
                   "\r\n"
                   "Commands:\r\n"
                   "\r\n"
                   "  netstar http --server\r\n"
                   "\r\n");
  } else if (string_equals(command->value, "redirect", true)) {
    if (command->values_count > 1) {
      netstar_command_redirect_command_help(command);
      netstar_exit(NETSTAR_EXIT_SUCCESS);
    }

    netstar_printf("Usage:\r\n"
                   "\r\n"
                   "  netstar redirect <command> [arguments]\r\n"
                   "\r\n"
                   "Commands:\r\n"
                   "\r\n"
                   "  netstar redirect --prerouting [redirect-routes]\r\n"
                   "\r\n");
  } else if (string_equals(command->value, "scanner", true)) {
    netstar_printf("Usage:\r\n\r\n"
                   "  netstar scanner [arguments]\r\n"
                   "\r\n"
                   "Arguments:\r\n"
                   "\r\n"
                   "  --scan-hosts4-cidr     scan active IPv4 hosts on the network from a CIDR annotation\r\n"
                   "  --scan-hosts4-range    scan IPv4 hosts from a range of addresses\r\n"
                   "  --scan-hosts4-only     scan only IPv4 hosts on the network\r\n"
                   "  --scan-hosts4-interval time interval between each scan for IPv4 hosts\r\n"
                   "\r\n"
                   "  --scan-hosts6-cidr     scan active IPv6 hosts on the network from a CIDR annotation\r\n"
                   "  --scan-hosts6-range    scan IPv6 hosts from a range of addresses\r\n"
                   "  --scan-hosts6-only     scan only IPv6 hosts on the network\r\n"
                   "  --scan-hosts6-interval time interval between each scan for IPv6 hosts\r\n"
                   "\r\n"
                   "  --stealth-scan         stealth host discovery based on network traffic only\r\n"
                   "\r\n"
                   "  --preexclude-hosts     skip a predefined list of IPv4 and IPv6 hosts during scanning\r\n"
                   "  --silent               silent notifications of discovered hosts\r\n"
                   "\r\n");
  } else if (string_equals(command->value, "monitor", true)) {
    netstar_printf("Usage:\r\n\r\n"
                   "  netstar monitor [argumente]\r\n"
                   "\r\n"
                   "Arguments:\r\n"
                   "\r\n"
                   "  --link-layer      monitor traffic at the link layer\r\n"
                   "  --network-layer   monitor traffic at the network layer\r\n"
                   "  --transport-layer monitor traffic at the transport layer\r\n"
                   "\r\n"
                   "  --filter          monitor network traffic specified by filter capture\r\n"
                   "\r\n"
                   "Filter syntax:\r\n\r\n"
                   "  [register] [operator==|operator!=] [constant] [operator&&|operator||] ...\r\n"
                   "  [operator!][constant]|[protocol] [operator&&|operator||] ...\r\n"
                   "\r\n"
                   "Operators:\r\n\r\n"
                   "  ==              equals logical operator\r\n"
                   "  !=              not logical equals operator\r\n"
                   "  >               greater than logical operator\r\n"
                   "  >=              greater or equals than logical operator\r\n"
                   "  <               less than logical operator\r\n"
                   "  <=              less or equals than logical operator\r\n"
                   "  &&              and logical operator\r\n"
                   "  ||              or logical operator\r\n"
                   "  !               not logical operator\r\n"
                   "\r\n"
                   "Protocols:\r\n\r\n"
                   "  arp             capture ARP packets\r\n"
                   "  arp-request     capture ARP request packets\r\n"
                   "  arp-reply       cpature ARP reply packets\r\n"
                   "  ip              capture IP (IPv4 and IPv6) packets\r\n"
                   "  ipv4            capture IPv4 packets\r\n"
                   "  ipv6            capture IPv6 packets\r\n"
                   "  icmp            capture ICMP (IPv4 and IPv6) packets\r\n"
                   "  icmpv4          capture ICMPv4 packets\r\n"
                   "  icmpv6          capture ICMPv6 packets\r\n"
                   "  ndp             capture NDP packets\r\n"
                   "  ndp-solicit     capture NDP solicitation packets\r\n"
                   "  ndp-advert      capture NDP adversiment packets\r\n"
                   "  tcp             capture TCP (IPv4 and IPv6) packets\r\n"
                   "  tcpv4           capture TCP/IPv4 packets\r\n"
                   "  tcpv6           capture TCP/IPv6 packets\r\n"
                   "  udp             capture UDP (IPv4 and IPv6) packets\r\n"
                   "  udpv4           capture UDP/IPv4 packets\r\n"
                   "  udpv6           capture UDP/IPv6 packets\r\n"
                   "\r\n"
                   "Registers:\r\n\r\n"
                   "  mac             network interface MAC address\r\n"
                   "  addr            network interface IP address\r\n"
                   "  addr4           network interface IPv4 address\r\n"
                   "  addr6           network interface IPv6 address\r\n"
                   "  smac            captured packet source MAC address\r\n"
                   "  dmac            captured packet destiny MAC address\r\n"
                   "  saddr           captured packet source IP address\r\n"
                   "  daddr           captured packet destiny IP address\r\n"
                   "  sport           captured packet source port\r\n"
                   "  dport           captured packet destiny port\r\n"
                   "\r\n"
                   "Constants:\r\n\r\n"
                   "  mac             00:00:DE:AD:BE:EF\r\n"
                   "  ipv4            192.168.1.1, 127.0.0.1\r\n"
                   "  ipv6            fe80::1, ::1\r\n"
                   "  port            80, 443, 53\r\n"
                   "\r\n");
  } else if (string_equals(command->value, "hosts", true)) {
    netstar_printf("Hosts are passed as a comma-separated list where each host has its respective MAC address (not required; resolved dynamically) and IP separated by a hyphen:\r\n"
                   "\r\n"
                   "  00:00:DE:AD:BE:EF-10.0.1.1,10.0.1.2-00:00:FE:EB:DA:ED\r\n"
                   "  10.0.1.1,10.0.1.2\r\n"
                   "\r\n"
                   "  00:00:DE:AD:BE:EF-fe80::1,fe80::2-00:00:FE:EB:DA:ED\r\n"
                   "  fe80::1,fe80::2\r\n"
                   "\r\n"
                   "Hosts can also be passed in files:\r\n"
                   "\r\n"
                   "  /relative-path/target-hosts-list.txt\r\n"
                   "  ./target-hosts-list.lst\r\n"
                   "\r\n");
  } else {
    netstar_printf("Unknown help topic \"%s\". Use \"netstar help\".\r\n", command->value);
  }

  netstar_exit(NETSTAR_EXIT_SUCCESS);
}

static void
netstar_command_help(struct console_args_command *command) {
  if (command->initialized)
    netstar_command_help_topic(command);

  netstar_printf("Netstar is a tool developed for exploiting layer2, layer3 and layer4 protocol attacks on local networks.\r\n\r\n");

  netstar_printf("Usage:\r\n\r\n"
                 "  netstar [-i|--iface] <iface> [commands] <arguments> ...\r\n"
                 "    -i|--iface           network interface/adapter primarily responsible for capturing and injecting packets\r\n"
              // "    -b|--bridge-iface    network interface/adapter for bridge mode\r\n"
                 "    --stealth            stealth mode using a custom/random MAC address\r\n"
                 "    --forward            forward captured/intercepted network traffic\r\n"
                 "\r\n");

  netstar_printf("Commands:\r\n\r\n");

  netstar_printf("  scanner  scan active hosts on the local network\r\n"
                 "    --scan-hosts4-cidr   scan active IPv4 hosts on the network from a CIDR annotation\r\n"
                 "    --scan-hosts4-range  scan IPv4 hosts from a range of addresses\r\n"
                 "    --scan-hosts4-only   scan only IPv4 hosts on the network\r\n"
                 "    --scan-hosts6-cidr   scan active IPv6 hosts on the network from a CIDR annotation\r\n"
                 "    --scan-hosts6-range  scan IPv6 hosts from a range of addresses\r\n"
                 "    --scan-hosts6-only   scan only IPv6 hosts on the network\r\n"
                 "\r\n");

  netstar_printf("  monitor  monitor network traffic\r\n"
                 "    --filter             monitor network traffic specified by filter capture\r\n"
                 "\r\n");

  netstar_printf("  redirect intercepted traffic port redirection\r\n"
                 "    --prerouting         redirection routes that apply to intercepted network traffic\r\n"
                 "\r\n");

  netstar_printf("  arp      ARP (Address Resolution Protocol) layer2 attacks\r\n"
                 "    --broadcast-spoofing spoofing attack by broadcast MAC address using ARP requests targeting IPv4 hosts\r\n"
                 "    --network-spoofing   spoofing attack targeting confirmed/scanned IPv4 hosts on the network\r\n"
                 "    --spoofing           spoofing attack targeting specific IPv4 hosts on the network\r\n"
                 "\r\n");

  netstar_printf("  ndp      NDP (Neighbor Discovery Protocol) layer3 attacks\r\n"
                 "    --network-spoofing   spoofing attack targeting confirmed/scanned IPv6 hosts on the network\r\n"
                 "    --spoofing           spoofing attack targeting specific IPv6 hosts on the network\r\n"
                 "\r\n");

  netstar_printf("  dns      DNS (Domain Name Service) layer4 attacks\r\n"
                 "    --spoofing           poisoning attack on intercepted network traffic targeting IPv4/IPv6 hosts\r\n"
                 "\r\n");

  netstar_printf("  http     HTTP (Hypertext Transfer Protocol) layer4 services\r\n"
                 "    --server             server-side service for redirect attacks\r\n"
                 "\r\n");

  netstar_printf("Use \"netstar help <command>\" for more information about that command.\r\n\r\n");

  netstar_printf("Additional help topics:\r\n\r\n"
                 "  hosts    assign host or a list of hosts to targets\r\n"
                 "\r\n");

  netstar_printf("Use \"netstar help <topic>\" for more information about that topic.\r\n\r\n");

  netstar_exit(NETSTAR_EXIT_SUCCESS);
}

static struct console_args_command netstar_help_command = {
  .name = "netstar:help", .flags = "-h|--help|help", .sensitive = true, .required = false, .required_values = 2,
  .routine = netstar_command_help,
};

static struct console_args_command *netstar_commands[] = {
  &netstar_forward_command,
  &netstar_managed_iface,

  &netstar_redirect_command,
  &netstar_stealth_command,

  &netstar_scanner_command,
  &netstar_monitor_command,

  &netstar_arp_command,
  &netstar_ndp_command,

  &netstar_dns_command,
  &netstar_http_command,

  &netstar_version_command,
  &netstar_about_command,
  &netstar_help_command,

  NULL
};

static console_args_parser_t netstar_args_parser;


static inline void
netstar_command_commands_parse(netstar_t *netstar) {
  if (!console_args_parser_defined(&netstar_args_parser) || (netstar_args_parser.defined == 1 && (netstar_managed_iface.defined || netstar_forward_command.defined)))
    netstar_command_help(&netstar_help_command);

// @ netstar:managed-interface
  if (netstar_managed_iface.defined && !netstar_managed_iface.initialized)
    netstar_error("%s: needs at least 1 argument; network interface/adapter name.\r\n", netstar_managed_iface.name);

  netstar_managed_interface_set(netstar, netstar_managed_iface.value);

// @ netstar:loopback-interface
  netstar_loopback_interface_set(netstar, NULL);

// @ netstar:stealth
  if (netstar_stealth_command.initialized && (netstar_stealth_command.values_count > 1 || !netstar_utils_args_macieee802(NULL, netstar_stealth_command.value)))
    netstar_error("%s: needs at least 1 argument; stealth MAC address.\r\n", netstar_stealth_command.name);

  if (netstar_stealth_command.defined)
    netstar_stealth(netstar, netstar_utils_stealth_macieee802(netstar_stealth_command.value));

  if (netstar_stealth_command.defined && ((netstar_managed_iface.defined && netstar_args_parser.defined) || netstar_args_parser.defined == 1))
    netstar_terminate();

// @ netstar:forward
  netstar_forward_set(netstar, netstar_forward_command.defined);

// netstar:scanner
  if (netstar_scanner_command.defined) {
    struct console_args_command *scan_hosts4_cidr = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:scan-hosts4-cidr");
    struct console_args_command *scan_hosts4_range = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:scan-hosts4-range");
    struct console_args_command *scan_hosts4_interval = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:scan-hosts4-interval");
    struct console_args_command *scan_hosts4_only = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:scan-hosts4-only");

    struct console_args_command *scan_hosts6_cidr = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:scan-hosts6-cidr");
    struct console_args_command *scan_hosts6_range = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:scan-hosts6-range");
    struct console_args_command *scan_hosts6_interval = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:scan-hosts6-interval");
    struct console_args_command *scan_hosts6_only = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:scan-hosts6-only");

    struct console_args_command *stealth_scan = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:stealth-scan");

    struct console_args_command *preexcluded_hosts = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:preexcluded-hosts");
    struct console_args_command *silent = console_args_command_subcommand(&netstar_scanner_command, "netstar:scanner:silent");

    struct netstar_service *service = netstar_service(netstar_scanner_command.name);
    struct netstar_scanner *scanner = (struct netstar_scanner *)service->context;

    if (netstar_scanner_new(scanner, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_scanner_command.name, system_error_reason(system_geterror()));

    if (preexcluded_hosts->defined && (!preexcluded_hosts->initialized || !netstar_utils_args_hosts(scanner->preexcluded_hosts, preexcluded_hosts->value)))
      netstar_error("%s: needs at least 1 argument; preexcluded hosts list.\r\n", preexcluded_hosts->name);

    if (scan_hosts4_cidr->defined && (!scan_hosts4_cidr->initialized || !netstar_utils_args_cidr4(&scanner->hosts4.range.begin, &scanner->hosts4.range.end, scan_hosts4_cidr->value)))
      netstar_error("%s: needs at least 1 argument; CIDR IPv4 address annotation.\r\n", scan_hosts4_cidr->name);

    if (scan_hosts4_range->defined && (!scan_hosts4_range->initialized || !netstar_utils_args_range4(&scanner->hosts4.range.begin, &scanner->hosts4.range.end, scan_hosts4_range->value)))
      netstar_error("%s: needs at least 2 arguments; begin and end range IPv4 addresses.\r\n", scan_hosts4_range->name);

    if (scan_hosts4_interval->defined && (!scan_hosts4_interval->initialized || !netstar_utils_args_time(&scanner->hosts4.time_interval, scan_hosts4_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", scan_hosts4_interval->name);

    if (scan_hosts4_only->defined)
      scanner->mode = NETSTAR_SCANNER_MODE_HOSTS4;

    if (scan_hosts6_cidr->defined && (!scan_hosts6_cidr->initialized || !netstar_utils_args_cidr6(&scanner->hosts6.range.begin, &scanner->hosts6.range.end, scan_hosts6_cidr->value)))
      netstar_error("%s: needs at least 1 argument; CIDR IPv6 address annotation.\r\n", scan_hosts6_cidr->name);

    if (scan_hosts6_range->defined && (!scan_hosts6_range->initialized || !netstar_utils_args_range6(&scanner->hosts6.range.begin, &scanner->hosts6.range.end, scan_hosts6_range->value)))
      netstar_error("%s: needs at least 2 arguments; begin and end range IPv6 addresses.\r\n", scan_hosts6_range->name);

    if (scan_hosts6_interval->defined && (!scan_hosts6_interval->initialized || !netstar_utils_args_time(&scanner->hosts6.time_interval, scan_hosts6_interval->value)))
      netstar_error("%s: needs at least 1 argument; timeout in minutes[m]/seconds[s]/milliseconds[ms].\r\n", scan_hosts6_interval->name);

    if (scan_hosts6_only->defined)
      scanner->mode = NETSTAR_SCANNER_MODE_HOSTS6;

    if (stealth_scan->defined)
      scanner->mode |= NETSTAR_SCANNER_MODE_STEALTH;

    scanner->silent = silent->defined;

    netstar_service_start(service);
  }

// netstar:redirect
  if (netstar_redirect_command.defined && !netstar_redirect_command.subcommands.defined)
    netstar_error("%s: must be accompanied by a subcommand. Use \"netstar help redirect\" for more information.\r\n\r\n", netstar_redirect_command.name);

  if (netstar_redirect_command.defined) {
    struct console_args_command *prerouting = console_args_command_subcommand(&netstar_redirect_command, "netstar:redirect:prerouting");
    struct console_args_command *preexcluded_hosts = console_args_command_subcommand(&netstar_redirect_command, "netstar:redirect:preexcluded-hosts");

    struct netstar_service *service = netstar_service(netstar_redirect_command.name);
    struct netstar_redirect *redirect = (struct netstar_redirect *)service->context;

    if (netstar_redirect_new(redirect, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_redirect_command.name, system_error_reason(system_geterror()));

    if (prerouting->defined && (!prerouting->initialized || !netstar_utils_args_preroutes(redirect->preroutes, prerouting->value)))
      netstar_error("%s: needs at least 1 argument; redirect preroutes list.\r\n", preexcluded_hosts->name);

    if (preexcluded_hosts->defined && (!preexcluded_hosts->initialized || !netstar_utils_args_hosts(redirect->preexcluded_hosts, preexcluded_hosts->value)))
      netstar_error("%s: needs at least 1 argument; preexcluded hosts list.\r\n", preexcluded_hosts->name);

    netstar_service_start(service);
  }

// netstar:monitor
  if (netstar_monitor_command.defined) {
    struct console_args_command *payload = console_args_command_subcommand(&netstar_monitor_command, "netstar:monitor:payload");
    struct console_args_command *layer2 = console_args_command_subcommand(&netstar_monitor_command, "netstar:monitor:link-layer");
    struct console_args_command *layer3 = console_args_command_subcommand(&netstar_monitor_command, "netstar:monitor:network-layer");
    struct console_args_command *layer4 = console_args_command_subcommand(&netstar_monitor_command, "netstar:monitor:transport-layer");

    struct console_args_command *filter = console_args_command_subcommand(&netstar_monitor_command, "netstar:monitor:filter");

    struct netstar_service *service = netstar_service(netstar_monitor_command.name);
    struct netstar_monitor *monitor = (struct netstar_monitor *)service->context;

    if (netstar_monitor_new(monitor, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_monitor_command.name, system_error_reason(system_geterror()));

    if (filter->defined && (!filter->initialized || !netstar_utils_args_filter(&monitor->filter, netstar, *filter->values)))
      netstar_error("%s: needs at least 1 argument; filter expression.\r\n", filter->name);

    if (layer2->defined || layer3->defined || layer4->defined)
      monitor->mode = 0x00;

    if (layer2->defined)
      monitor->mode |= NETSTAR_MONITOR_MODE_LAYER2;

    if (layer3->defined)
      monitor->mode |= NETSTAR_MONITOR_MODE_LAYER3;

    if (layer4->defined)
      monitor->mode |= NETSTAR_MONITOR_MODE_LAYER4;

    if (payload->defined && (!payload->initialized || !netstar_utils_args_payloadformat(&monitor->payload_format, *payload->values)))
      netstar_error("%s: needs at least 1 argument; payload format.\r\n", payload->name);

    if (payload->defined)
      monitor->mode |= NETSTAR_MONITOR_MODE_PAYLOAD;

    netstar_service_start(service);
  }

// netstar:arp
  if (netstar_arp_command.defined && !netstar_arp_command.subcommands.defined)
    netstar_error("%s: must be accompanied by a subcommand. Use \"netstar help arp\" for more information.\r\n\r\n", netstar_arp_command.name);

  if (netstar_arp_broadcast_spoofing_command.defined) {
    struct console_args_command *spoof_steady_interval = console_args_command_subcommand(&netstar_arp_broadcast_spoofing_command, "netstar:arp:broadcast-spoofing:spoof-steady-interval");

    struct console_args_command *spoof_burst_interval = console_args_command_subcommand(&netstar_arp_broadcast_spoofing_command, "netstar:arp:broadcast-spoofing:spoof-burst-interval");
    struct console_args_command *spoof_burst_count = console_args_command_subcommand(&netstar_arp_broadcast_spoofing_command, "netstar:arp:broadcast-spoofing:spoof-burst-count");

    struct netstar_service *service = netstar_service(netstar_arp_broadcast_spoofing_command.name);
    struct netstar_arp_broadcast_spoofing *spoofing_attack = (struct netstar_arp_broadcast_spoofing *)service->context;

    if (netstar_arp_broadcast_spoofing_new(spoofing_attack, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", &netstar_arp_broadcast_spoofing_command.name, system_error_reason(system_geterror()));

    if (!netstar_arp_broadcast_spoofing_command.initialized || !netstar_utils_args_hosts4(spoofing_attack->spoofed_hosts, netstar_arp_broadcast_spoofing_command.value))
      netstar_error("%s: needs at least 1 argument; spoofed IPv4 hosts list.\r\n", netstar_arp_broadcast_spoofing_command.name); // "Use \"netstar help arp\" for more information.\r\n\r\n";

    if (spoof_burst_interval->defined && (!spoof_burst_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_burst_interval, spoof_burst_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in seconds/milliseconds.\r\n", spoof_burst_interval->name);

    if (spoof_burst_count->defined && (!spoof_burst_count->initialized || !netstar_utils_args_number((uint64_t *)&spoofing_attack->spoof_burst_count, spoof_burst_count->value)))
      netstar_error("%s: needs at least 1 argument; unsigned number.\r\n", spoof_burst_count->name);

    if (spoof_steady_interval->defined && (!spoof_steady_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_steady_interval, spoof_steady_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_steady_interval->name);

    netstar_service_start(service);
  }

// netstar:arp:network-spoofing
  if (netstar_arp_network_spoofing_command.defined) {
    struct console_args_command *network_scan_interval = console_args_command_subcommand(&netstar_arp_network_spoofing_command, "netstar:arp:network-spoofing:network-scan-interval");

    struct console_args_command *spoof_steady_interval = console_args_command_subcommand(&netstar_arp_network_spoofing_command, "netstar:arp:network-spoofing:spoof-steady-interval");

    struct console_args_command *spoof_burst_interval = console_args_command_subcommand(&netstar_arp_network_spoofing_command, "netstar:arp:network-spoofing:spoof-burst-interval");
    struct console_args_command *spoof_burst_count = console_args_command_subcommand(&netstar_arp_network_spoofing_command, "netstar:arp:network-spoofing:spoof-burst-count");

    struct console_args_command *redirection_host = console_args_command_subcommand(&netstar_arp_network_spoofing_command, "netstar:arp:network-spoofing:redirection-host");
    struct console_args_command *bidirectional = console_args_command_subcommand(&netstar_arp_network_spoofing_command, "netstar:arp:network-spoofing:bidirectional");

    struct console_args_command *protected_hosts = console_args_command_subcommand(&netstar_arp_network_spoofing_command, "netstar:arp:network-spoofing:protected-hosts");

    struct netstar_service *service = netstar_service(netstar_arp_network_spoofing_command.name);
    struct netstar_arp_network_spoofing *spoofing_attack = (struct netstar_arp_network_spoofing *)service->context;

    if (netstar_arp_network_spoofing_new(spoofing_attack, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_arp_network_spoofing_command.name, system_error_reason(system_geterror()));

    if (!netstar_arp_network_spoofing_command.initialized || !netstar_utils_args_hosts4(spoofing_attack->spoofed_hosts, netstar_arp_network_spoofing_command.value))
      netstar_error("%s: needs at least 1 argument; spoofed IPv4 hosts list.\r\n", netstar_arp_network_spoofing_command.name); // "Use \"netstar help arp\" for more information.\r\n\r\n";

    if (protected_hosts->defined && !netstar_utils_args_hosts4(spoofing_attack->protected_hosts, protected_hosts->value))
      netstar_error("%s: needs at least 1 argument; protected IPv4 hosts list.\r\n", protected_hosts->name);

    if (redirection_host->defined && !netstar_utils_args_host4(&spoofing_attack->redirection_host, redirection_host->value))
      netstar_error("%s: needs at least 1 argument; redirection IPv4 host.\r\n", redirection_host->name);

    spoofing_attack->redirective = redirection_host->defined;

    spoofing_attack->bidirectional = bidirectional->defined;

    if (network_scan_interval->defined && (!network_scan_interval->initialized || !netstar_utils_args_time(&spoofing_attack->network_scan_interval, network_scan_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", network_scan_interval->name);

    if (spoof_burst_interval->defined && (!spoof_burst_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_burst_interval, spoof_burst_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_burst_interval->name);

    if (spoof_burst_count->defined && (!spoof_burst_count->initialized || !netstar_utils_args_number((uint64_t *)&spoofing_attack->spoof_burst_count, spoof_burst_count->value)))
      netstar_error("%s: needs at least 1 argument; unsigned number.\r\n", spoof_burst_count->name);

    if (spoof_steady_interval->defined && (!spoof_steady_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_steady_interval, spoof_steady_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_steady_interval->name);

    netstar_service_start(service);
  }
// netstar:arp:spoofing
  if (netstar_arp_spoofing_command.defined) {
    struct console_args_command *redirection_host = console_args_command_subcommand(&netstar_arp_spoofing_command, "netstar:arp:spoofing:redirection-hosts");
    struct console_args_command *bidirectional = console_args_command_subcommand(&netstar_arp_spoofing_command, "netstar:arp:spoofing:bidirectional");

    struct console_args_command *spoof_steady_interval = console_args_command_subcommand(&netstar_arp_spoofing_command, "netstar:arp:spoofing:spoof-steady-interval");

    struct console_args_command *spoof_burst_interval = console_args_command_subcommand(&netstar_arp_spoofing_command, "netstar:arp:spoofing:spoof-burst-interval");
    struct console_args_command *spoof_burst_count = console_args_command_subcommand(&netstar_arp_spoofing_command, "netstar:arp:spoofing:spoof-burst-count");

    struct netstar_service *service = netstar_service(netstar_arp_spoofing_command.name);
    struct netstar_arp_spoofing *spoofing_attack = (struct netstar_arp_spoofing *)service->context;

    if (netstar_arp_spoofing_new(spoofing_attack, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_arp_spoofing_command.name, system_error_reason(system_geterror()));

    if (!netstar_arp_spoofing_command.initialized || netstar_arp_spoofing_command.values_count < 2 ||
        !netstar_utils_args_hosts4(spoofing_attack->spoofed_hosts, netstar_arp_spoofing_command.values[0]) ||
        !netstar_utils_args_hosts4(spoofing_attack->target_hosts, netstar_arp_spoofing_command.values[1])
    )
      netstar_error("%s: needs at least 2 arguments; spoofed and target IPv4 hosts list.\r\n", netstar_arp_spoofing_command.name); // "Use \"netstar help arp\" for more information.\r\n\r\n";

    if (redirection_host->defined && !netstar_utils_args_host4(&spoofing_attack->redirection_host, *redirection_host->values))
      netstar_error("%s: needs at least 1 argument; redirection IPv4 host.\r\n", redirection_host->name);

    spoofing_attack->redirective = redirection_host->defined;

    spoofing_attack->bidirectional = bidirectional->defined;

    if (spoof_burst_interval->defined && (!spoof_burst_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_burst_interval, spoof_burst_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_burst_interval->name);

    if (spoof_burst_count->defined && (!spoof_burst_count->initialized || !netstar_utils_args_number((uint64_t *)&spoofing_attack->spoof_burst_count, spoof_burst_count->value)))
      netstar_error("%s: needs at least 1 argument; unsigned number.\r\n", spoof_burst_count->name);

    if (spoof_steady_interval->defined && (!spoof_steady_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_steady_interval, spoof_steady_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_steady_interval->name);

    netstar_service_start(service);
  }

// netstar:ndp
  if (netstar_ndp_command.defined && !netstar_ndp_command.subcommands.defined)
    netstar_error("%s: must be accompanied by a subcommand. Use \"netstar help ndp\" for more information.\r\n\r\n", netstar_ndp_command.name);

// netstar:ndp:network-spoofing
  if (netstar_ndp_network_spoofing_command.defined) {
    struct console_args_command *network_scan_interval = console_args_command_subcommand(&netstar_ndp_network_spoofing_command, "netstar:ndp:network-spoofing:network-scan-interval");

    struct console_args_command *spoof_steady_interval = console_args_command_subcommand(&netstar_ndp_network_spoofing_command, "netstar:ndp:network-spoofing:spoof-steady-interval");

    struct console_args_command *spoof_burst_interval = console_args_command_subcommand(&netstar_ndp_network_spoofing_command, "netstar:ndp:network-spoofing:spoof-burst-interval");
    struct console_args_command *spoof_burst_count = console_args_command_subcommand(&netstar_ndp_network_spoofing_command, "netstar:ndp:network-spoofing:spoof-burst-count");

    struct console_args_command *redirection_host = console_args_command_subcommand(&netstar_ndp_network_spoofing_command, "netstar:ndp:network-spoofing:redirection-host");
    struct console_args_command *bidirectional = console_args_command_subcommand(&netstar_ndp_network_spoofing_command, "netstar:ndp:network-spoofing:bidirectional");

    struct console_args_command *protected_hosts = console_args_command_subcommand(&netstar_ndp_network_spoofing_command, "netstar:ndp:network-spoofing:protected-hosts");

    struct netstar_service *service = netstar_service(netstar_ndp_network_spoofing_command.name);
    struct netstar_ndp_network_spoofing *spoofing_attack = (struct netstar_ndp_network_spoofing *)service->context;

    if (netstar_ndp_network_spoofing_new(spoofing_attack, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_ndp_network_spoofing_command.name, system_error_reason(system_geterror()));

    if (!netstar_ndp_network_spoofing_command.initialized || !netstar_utils_args_hosts6(spoofing_attack->spoofed_hosts, netstar_ndp_network_spoofing_command.value))
      netstar_error("%s: needs at least 1 argument; spoofed IPv6 hosts list.\r\n", netstar_ndp_network_spoofing_command.name);

    if (network_scan_interval->defined && (!network_scan_interval->initialized || !netstar_utils_args_time(&spoofing_attack->network_scan_interval, network_scan_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_burst_interval->name);

    if (spoof_burst_interval->defined && (!spoof_burst_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_burst_interval, spoof_burst_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_burst_interval->name);

    if (spoof_burst_count->defined && (!spoof_burst_count->initialized || !netstar_utils_args_number((uint64_t *)&spoofing_attack->spoof_burst_count, spoof_burst_count->value)))
      netstar_error("%s: needs at least 1 argument; unsigned number.\r\n", spoof_burst_count->name);

    if (spoof_steady_interval->defined && (!spoof_steady_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_steady_interval, spoof_steady_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_steady_interval->name);

    if (protected_hosts->defined && !netstar_utils_args_hosts6(spoofing_attack->protected_hosts, protected_hosts->value))
      netstar_error("%s: needs at least 1 argument; protected IPv6 hosts list.\r\n", protected_hosts->name);

    if (redirection_host->defined && !netstar_utils_args_host6(&spoofing_attack->redirection_host, redirection_host->value))
      netstar_error("%s: needs at least 1 argument; redirection IPv6 host.\r\n", redirection_host->name);

    spoofing_attack->redirective = redirection_host->defined;

    spoofing_attack->bidirectional = bidirectional->defined;

    netstar_service_start(service);
  }
// netstar:ndp:spoofing
  if (netstar_ndp_spoofing_command.defined) {
    struct console_args_command *spoof_steady_interval = console_args_command_subcommand(&netstar_ndp_spoofing_command, "netstar:ndp:spoofing:spoof-steady-interval");

    struct console_args_command *spoof_burst_interval = console_args_command_subcommand(&netstar_ndp_spoofing_command, "netstar:ndp:spoofing:spoof-burst-interval");
    struct console_args_command *spoof_burst_count = console_args_command_subcommand(&netstar_ndp_spoofing_command, "netstar:ndp:spoofing:spoof-burst-count");

    struct console_args_command *bidirectional = console_args_command_subcommand(&netstar_ndp_spoofing_command, "netstar:ndp:spoofing:bidirectional");

    struct netstar_service *service = netstar_service(netstar_ndp_spoofing_command.name);
    struct netstar_ndp_spoofing *spoofing_attack = (struct netstar_ndp_spoofing *)service->context;

    if (netstar_ndp_spoofing_new(spoofing_attack, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_ndp_spoofing_command.name, system_error_reason(system_geterror()));

    if (!netstar_ndp_spoofing_command.initialized ||
        !netstar_utils_args_hosts6(spoofing_attack->spoofed_hosts, netstar_ndp_spoofing_command.values[0]) ||
        !netstar_utils_args_hosts6(spoofing_attack->target_hosts, netstar_ndp_spoofing_command.values[1])
    )
      netstar_error("%s: needs at least 2 arguments; spoofed and target IPv6 hosts list.\r\n", netstar_ndp_spoofing_command.name);

    if (spoof_steady_interval->defined && (!spoof_steady_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_steady_interval, spoof_steady_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_steady_interval->name);
 
    if (spoof_burst_interval->defined && (!spoof_burst_interval->initialized || !netstar_utils_args_time(&spoofing_attack->spoof_burst_interval, spoof_burst_interval->value)))
      netstar_error("%s: needs at least 1 argument; time in minutes[m]/seconds[s]/milliseconds[ms].\r\n", spoof_burst_interval->name);

    if (spoof_burst_count->defined && (!spoof_burst_count->initialized || !netstar_utils_args_number((uint64_t *)&spoofing_attack->spoof_burst_count, spoof_burst_count->value)))
      netstar_error("%s: needs at least 1 argument; unsigned number.\r\n", spoof_burst_count->name);

    spoofing_attack->bidirectional = bidirectional->defined;

    netstar_service_start(service);
  }

// netstar:dns
  if (netstar_dns_command.defined && !netstar_dns_command.subcommands.defined)
    netstar_error("%s: must be accompanied by a subcommand. Use \"netstar help dns\" for more information.\r\n\r\n", netstar_dns_command.name);

// netstar:dns:spoofing
  if (netstar_dns_spoofing_command.defined) {
    struct console_args_command *protected_hosts = console_args_command_subcommand(&netstar_dns_spoofing_command, "netstar:dns:spoofing:protected-hosts");
    struct console_args_command *target_hosts = console_args_command_subcommand(&netstar_dns_spoofing_command, "netstar:dns:spoofing:target-hosts");

    struct netstar_service *service = netstar_service(netstar_dns_spoofing_command.name);
    struct netstar_dns_spoofing *spoofing_attack = (struct netstar_dns_spoofing *)service->context;

    if (netstar_dns_spoofing_new(spoofing_attack, netstar) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_dns_spoofing_command.name, system_error_reason(system_geterror()));

    if (!netstar_dns_spoofing_command.initialized || !netstar_utils_args_resources(spoofing_attack->resources, netstar_dns_spoofing_command.value))
      netstar_error("%s: needs at least 1 argument; resource records list.\r\n", netstar_ndp_spoofing_command.name);

    if (target_hosts->defined && (!target_hosts->initialized || !netstar_utils_args_hosts(spoofing_attack->target_hosts, target_hosts->value)))
      netstar_error("%s: needs at least 1 argument; target hosts list.\r\n", target_hosts->name);

    if (protected_hosts->defined && (!protected_hosts->initialized || !netstar_utils_args_hosts(spoofing_attack->protected_hosts, protected_hosts->value)))
      netstar_error("%s: needs at least 1 argument; protected hosts list.\r\n", protected_hosts->name);
 
    netstar_service_start(service);
  }

// netstar:http
  if (netstar_http_command.defined && !netstar_http_server_command.defined)
    netstar_error("%s: must be accompanied by a subcommand. Use \"netstar help http\" for more information.\r\n\r\n", netstar_http_command.name);

  if (netstar_http_server_command.defined) {
    struct netstar_service *service = netstar_service(netstar_http_server_command.name);
    struct netstar_http_server *server = (struct netstar_http_server *)service->context;

    if (netstar_http_server_new(server) == -1)
      netstar_critical("%s: syscall-error: %s\r\n", netstar_http_server_command.name, system_error_reason(system_geterror()));

    netstar_service_start(service);
  }
}

int
netstar_command_initialize(netstar_t *netstar, int argc, char **argv) {
  if (console_args_parser_initialize(&netstar_args_parser, netstar_commands, argc, argv) == -1)
    return -1;

  console_args_parser_parse(&netstar_args_parser);

  netstar_command_commands_parse(netstar);

  return 1;
}

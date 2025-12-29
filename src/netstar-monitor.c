#include "netstar-monitor.h"

#include <netstar-services.h>
#include <netstar-threads.h>

#include <netstar-capture.h>

#include <netstar-utils.h>

#include <buffers/buffers.h>
#include <strings/strings.h>

#include <ctype.h>


static bool netstar_monitor_initialized, netstar_monitor_started;

static buffer_t *netstar_monitor_buffer;


#define netstar_monitor_value(value) (const char *)buffer_ptr(monitor->dissector.buffers[value])


static void
netstar_monitor_format(const char *format, size_t spaced, ...) {
  va_list args;

  if (!format || string_isempty(format))
    return;

  va_start(args, spaced);
  netstar_utils_string_vformat(netstar_monitor_buffer, format, args);
  va_end(args);

  if (spaced > 0)
    netstar_utils_string_format(netstar_monitor_buffer, "%*s", spaced, " ");
}


static void
netstar_monitor_write(const char *string) {
  if (string && !string_isempty(string))
    netstar_monitor_format("%s", 2, string);
}

static inline uint8_t *
netstar_monitor_packet_payload(struct netstar_capture_packet *packet, size_t *length) {
  if (packet->layer4.payload && packet->layer4.payload_length) {
    *length = packet->layer4.payload_length;
    return packet->layer4.payload;
  }

  if (packet->layer3.payload && packet->layer3.payload_length) {
    *length = packet->layer3.payload_length;
    return packet->layer3.payload;
  }

  if (packet->layer2.payload && packet->layer2.payload_length) {
    *length = packet->layer2.payload_length;
    return packet->layer2.payload;
  }

  return NULL;
}

static void
netstar_monitor_payload_format(struct netstar_capture_packet *packet, netstar_monitor_payload_format_t payload_format) {
  static const char *payload_formats[] = { "%02X", "%02o", "%" PRIu8 };
  size_t payload_length = 0, byte;
  uint8_t *payload = NULL;

  if (!(payload = netstar_monitor_packet_payload(packet, &payload_length)))
    return;

  netstar_monitor_format("\r\n", 0);

  for (byte = 0; byte < payload_length; byte++) {
    if (payload_format == NETSTAR_MONITOR_PAYLOAD_DATA_ASCII) {
      char ascii = (isgraph((char)payload[byte]) && !isspace((char)payload[byte]) ? payload[byte] : '.');
      netstar_monitor_format("%c", 0, ascii);
      continue;
    }

    netstar_monitor_format(payload_formats[payload_format], 1, payload[byte]);
  }
}

static inline bool
netstar_monitor_link_layer_information(struct netstar_monitor *monitor, struct netstar_capture_packet *packet) {
  return ((monitor->mode & NETSTAR_MONITOR_MODE_LAYER2) && (packet->layer & NETSTAR_FORWARD_LAYER2));
}

static inline bool
netstar_monitor_link_layer_protocol(struct netstar_monitor *monitor, struct netstar_capture_packet *packet) {
  return ((monitor->mode & (NETSTAR_MONITOR_MODE_LAYER2|NETSTAR_MONITOR_MODE_LAYER3)) && (packet->layer & (NETSTAR_FORWARD_LAYER2|NETSTAR_FORWARD_LAYER3)));
}

static inline bool
netstar_monitor_network_layer_information(struct netstar_monitor *monitor, struct netstar_capture_packet *packet) {
  return ((monitor->mode & NETSTAR_MONITOR_MODE_LAYER3) && (packet->layer & NETSTAR_FORWARD_LAYER3)) &&
         !(monitor->mode == NETSTAR_MONITOR_MODE_LAYER4);
}

static inline bool
netstar_monitor_network_layer_protocol(struct netstar_monitor *monitor, struct netstar_capture_packet *packet) {
  return ((monitor->mode & (NETSTAR_MONITOR_MODE_LAYER3|NETSTAR_MONITOR_MODE_LAYER4)) && (packet->layer & (NETSTAR_FORWARD_LAYER3|NETSTAR_FORWARD_LAYER4))) &&
         !(monitor->mode == NETSTAR_MONITOR_MODE_LAYER4 && !(packet->layer & NETSTAR_MONITOR_MODE_LAYER4));
}

static inline bool
netstar_monitor_transport_layer_information(struct netstar_monitor *monitor, struct netstar_capture_packet *packet) {
  return ((monitor->mode & NETSTAR_MONITOR_MODE_LAYER4) && (packet->layer & NETSTAR_FORWARD_LAYER4));
}

static inline bool
netstar_monitor_packet_information(struct netstar_monitor *monitor, struct netstar_capture_packet *packet) {
  return ((monitor->mode & (NETSTAR_MONITOR_MODE_LAYER3|NETSTAR_MONITOR_MODE_LAYER4)) && (packet->layer & (NETSTAR_FORWARD_LAYER3|NETSTAR_FORWARD_LAYER4)) &&
         !(monitor->mode == NETSTAR_MONITOR_MODE_LAYER3 && (packet->layer & NETSTAR_FORWARD_LAYER4))) &&
         !(monitor->mode == NETSTAR_MONITOR_MODE_LAYER4 && !(packet->layer & NETSTAR_FORWARD_LAYER4));
}

static inline bool
netstar_monitor_packet_payload_information(struct netstar_monitor *monitor, struct netstar_capture_packet *packet) {
  return (monitor->mode & NETSTAR_MONITOR_MODE_PAYLOAD);
}

static inline bool
netstar_monitor_built_information_not_required(void) {
  return buffer_length(netstar_monitor_buffer) == 0;
}

static bool
netstar_monitor_dissect(struct netstar_monitor *monitor, struct netstar_capture_packet *packet) {
// if (monitor->mode == NETSTAR_MONITOR_MODE_LAYER2 && (packet->layer & (NETSTAR_FORWARD_LAYER3|NETSTAR_FORWARD_LAYER4)))
//   return false;
// if (monitor->mode == NETSTAR_MONITOR_MODE_LAYER4 && !(packet->layer & NETSTAR_FORWARD_LAYER4))
//   return false;

  netstar_dissector_dissect(&monitor->dissector, packet);

  buffer_truncate(netstar_monitor_buffer, 0);

  if (netstar_monitor_link_layer_information(monitor, packet)) {
    netstar_monitor_format("%s - %s", 2, netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_SOURCE_HARDWARE),
      netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_DESTINATION_HARDWARE));
  }

  if (netstar_monitor_link_layer_protocol(monitor, packet)) {
    netstar_monitor_write(netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_ETHERNET_PROTOCOL));
  }

  if (netstar_monitor_network_layer_information(monitor, packet)) {
    netstar_monitor_format("%s - %s", 2, netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_SOURCE_ADDRESS),
      netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_DESTINATION_ADDRESS));
  }

  if (netstar_monitor_network_layer_protocol(monitor, packet)) {
    netstar_monitor_write(netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_IP_PROTOCOL));
  }

  if (netstar_monitor_transport_layer_information(monitor, packet)) {
    netstar_monitor_format("%s - %s", 2, netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_SOURCE_PORT),
      netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_DESTINATION_PORT));

    netstar_monitor_write(netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_APPLICATION_PROTOCOL));
  }

  if (netstar_monitor_packet_information(monitor, packet)) {
    netstar_monitor_write(netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_INFORMATION));
  }

  if (netstar_monitor_packet_payload_information(monitor, packet)) {
    netstar_monitor_payload_format(packet, monitor->payload_format);
  }

  if (netstar_monitor_built_information_not_required())
    return false;

/*
  if ((monitor->mode & NETSTAR_MONITOR_MODE_LAYER2) && (packet->layer & NETSTAR_FORWARD_LAYER2)) {
    netstar_monitor_format("%s - %s", 2, netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_SOURCE_HARDWARE),
      netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_DESTINATION_HARDWARE));
  }

  if ((monitor->mode & (NETSTAR_MONITOR_MODE_LAYER2|NETSTAR_MONITOR_MODE_LAYER3)) && (packet->layer & (NETSTAR_FORWARD_LAYER2|NETSTAR_FORWARD_LAYER3))) {
    netstar_monitor_write(netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_ETHERNET_PROTOCOL));
  }

  if ((monitor->mode & NETSTAR_MONITOR_MODE_LAYER3) && (packet->layer & NETSTAR_FORWARD_LAYER3)) {
    netstar_monitor_format("%s - %s", 2, netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_SOURCE_ADDRESS),
      netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_DESTINATION_ADDRESS));
  }

  if ((monitor->mode & (NETSTAR_MONITOR_MODE_LAYER3|NETSTAR_MONITOR_MODE_LAYER4)) && (packet->layer & (NETSTAR_FORWARD_LAYER3|NETSTAR_FORWARD_LAYER4))) {
    netstar_monitor_write(netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_IP_PROTOCOL));
  }

  if ((monitor->mode & NETSTAR_MONITOR_MODE_LAYER4) && (packet->layer & NETSTAR_FORWARD_LAYER4)) {
    netstar_monitor_format("%s - %s", 2, netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_SOURCE_PORT),
      netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_DESTINATION_PORT));

    netstar_monitor_write(netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_APPLICATION_PROTOCOL));
  }

  if ((monitor->mode & (NETSTAR_MONITOR_MODE_LAYER3|NETSTAR_MONITOR_MODE_LAYER4)) && (packet->layer & (NETSTAR_FORWARD_LAYER3|NETSTAR_FORWARD_LAYER4))) {
    netstar_monitor_write(netstar_monitor_value(NETSTAR_DISSECTOR_PACKET_INFORMATION));
  }

  if ((monitor->mode & NETSTAR_MONITOR_MODE_PAYLOAD)) {
    netstar_monitor_payload_format(packet, monitor->payload_format);
  }


  if (!buffer_length(netstar_monitor_buffer))
    return false;
*/

  netstar_monitor_format("\r\n", 0);
  return true;
}

static void
netstar_monitor(netstar_t *netstar, struct netstar_capture_packet *packet, void *args) {
  struct netstar_monitor *monitor = (struct netstar_monitor *)args;

  if (netstar_filter_initialized(&monitor->filter) && !netstar_filter_compile(&monitor->filter, packet))
    return;

  if (!netstar_monitor_dissect(monitor, packet))
    return;

  netstar_log("\b \b[ monitor ] %s", (char *)buffer_ptr(netstar_monitor_buffer));
}

static void
netstar_monitor_initialize(netstar_t *netstar, void *context) {
  if (netstar_monitor_initialized)
    return;

  if (!(netstar_monitor_buffer = buffer_new()))
    return;

  netstar_monitor_initialized = true;
}

static void
netstar_monitor_deinitialize(void *context) {
  struct netstar_monitor *monitor = (struct netstar_monitor *)context;

  if (!netstar_monitor_initialized)
    return;

  buffer_free(netstar_monitor_buffer);
  netstar_monitor_buffer = NULL;

  netstar_monitor_free(monitor);

  netstar_monitor_initialized = false;
}

static void
netstar_monitor_start(void *context) {
  struct netstar_monitor *monitor = (struct netstar_monitor *)context;

  if (netstar_monitor_started)
    return;

  netstar_forward_add(netstar_monitor, NETSTAR_FORWARD_ANY, monitor);

  netstar_monitor_started = true;
}

static void
netstar_monitor_stop(void *context) {
  if (!netstar_monitor_started)
    return;

  netstar_forward_remove(netstar_monitor);

  netstar_monitor_started = false;
}

int
netstar_monitor_new(struct netstar_monitor *monitor, netstar_t *netstar) {
  if (netstar_dissector_initialize(&monitor->dissector) == -1)
    return -1;
 
  monitor->mode = NETSTAR_MONITOR_MODE_NORMAL;
  monitor->netstar = netstar;

  return 1;
}

void
netstar_monitor_free(struct netstar_monitor *monitor) {
  if (monitor) {
    netstar_dissector_deinitialize(&monitor->dissector);

    netstar_filter_free(&monitor->filter);
  }
}

static struct netstar_monitor netstar_monitor_context;

static struct netstar_service netstar_monitor_context_service = {
  netstar_monitor_initialize, netstar_monitor_deinitialize,
  netstar_monitor_start, netstar_monitor_stop,
  "netstar:monitor", &netstar_monitor_context,
};

struct netstar_service *
netstar_monitor_service(void) {
  return &netstar_monitor_context_service;
}

__attribute__((__constructor__))
static inline void
netstar_monitor_register_service(void) {
  netstar_services_register(netstar_monitor_service());
}

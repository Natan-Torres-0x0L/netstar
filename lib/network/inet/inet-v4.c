#include "inet-v4.h"

#if defined _WIN16 || defined _WIN32 || defined _WIN64 || defined __WIN32__ || defined __TOS_WIN__ || defined __WINDOWS__
  #include <winsock2.h>

#else // elif defined __unix__ || defined __unix
  #include <netinet/in.h>

#endif

#include <strings/strings.h>
#include <string.h>

#include <inttypes.h>
#include <stdio.h>


const struct inetv4 inetv4_broadcast  = INETV4_IBROADCAST;

const struct inetv4 inetv4_loopback   = INETV4_ILOOPBACK;

const struct inetv4 inetv4_all        = INETV4_IALL;

const struct inetv4 inetv4_allnodes   = INETV4_IALLNODES;
const struct inetv4 inetv4_allrouters = INETV4_IALLROUTERS; 


static inline int8_t
inetv4_decimal(char character) {
  return ((character >= '0' && character <= '9') ? (character-'0') : (-1));
}

int
inetv4_parse(struct inetv4 *network, const char *string) {
  uint8_t bytes[INETV4_SIZE] = {0};
  uint16_t value, size = 0, digits;

  if (!string || !*string)
    return -1;

  for (;;) {
    for (value = digits = 0; digits < 3 && *string && inetv4_decimal(*string) >= 0; string++, digits++)
      value = (uint16_t)(10*value+(uint8_t)inetv4_decimal(*string));

    if ((*string && *string != '.') || (*string && !*(string+1) && *string == '.'))
      return -1;
    if (digits == 0 || size > 3 || value > 0xFF)
      return -1;

    bytes[(size++) & 3] = (uint8_t)value;

    if (!*string) {
      if (size != INETV4_SIZE /* 255.255.255.255 */)
        return -1;

      break;
    }

    string++;
  }

  if (network)
    memcpy(network, bytes, INETV4_SIZE);

  return 1;
}

char *
inetv4_format(const struct inetv4 *network, char *string, size_t length) {
  char source[INETV4_STRLENGTH] = {0};

  string_zero(source, sizeof(source));

  snprintf(source, sizeof(source), "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8, network->u8[0], network->u8[1], network->u8[2], network->u8[3]);

  if (string)
    return (char *)memcpy(string, source, length);

  return string_new(source);
}

bool
inetv4_ismulticast(const struct inetv4 *network) {
  return ((htonl(network->u32) & 0xF0000000) == 0xE0000000);
}

bool
inetv4_isloopback(const struct inetv4 *network) {
  return !memcmp(network, &INETV4_LOOPBACK, INETV4_SIZE);
}

bool
inetv4_isclassa(const struct inetv4 *network) {
  return ((htonl(network->u32) & 0x80000000) == 0);
}

bool
inetv4_isclassb(const struct inetv4 *network) {
  return ((htonl(network->u32) & 0xC0000000) == 0x80000000);
}

bool
inetv4_isclassc(const struct inetv4 *network) {
  return ((htonl(network->u32) & 0xE0000000) == 0xC0000000);
}

int
inetv4_compare(const struct inetv4 *network1, const struct inetv4 *network2) {
  uint8_t byte;

  for (byte = 0; byte < INETV4_SIZE; byte++)
    if (network1->u8[byte] < network2->u8[byte])
      return -1;
    else if (network1->u8[byte] > network2->u8[byte])
      return 1;

  return 0;
}

int
inetv4_cidr(const char *cidr, uint8_t *prefix_length, struct inetv4 *network, struct inetv4 *netmask) {
  uint32_t netmasku32 = INETV4_UALL;
  struct inetv4 addr = {0};

  uint8_t prefix = 0;

  if (sscanf(cidr, "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8 "/%" SCNu8, &addr.u8[0], &addr.u8[1], &addr.u8[2], &addr.u8[3], &prefix) != 5)
    return -1;

  if (prefix > 32)
    return -1;

  if (prefix_length)
    *prefix_length = prefix;

  if (prefix)
    netmasku32 = htonl((0xFFFFFFFF << (32-prefix)) & 0xFFFFFFFF);

  if (netmask)
    netmask->u32 = netmasku32;

  if (network)
    network->u32 = (addr.u32 & netmasku32);

  return 0;
}

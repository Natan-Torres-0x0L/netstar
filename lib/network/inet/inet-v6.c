#include "inet-v6.h"
#include "inet-v4.h"

#include <strings/strings.h>
#include <string.h>

#include <inttypes.h>
#include <stdio.h>


const struct inetv6 inetv6_loopback   = INETV6_ILOOPBACK;

const struct inetv6 inetv6_all        = INETV6_IALL;

const struct inetv6 inetv6_allnodes   = INETV6_IALLNODES;
const struct inetv6 inetv6_allrouters = INETV6_IALLROUTERS;


static inline int8_t
inetv6_hexadecimal(char character) {
  if (character >= '0' && character <= '9')
    return character-'0';
  
  if (character >= 'a' && character <= 'f')
    return character-'a'+10;

  if (character >= 'A' && character <= 'F')
    return character-'A'+10;

  return -1;
}

int
inetv6_parse(struct inetv6 *network, const char *string) {
  uint16_t bytes[8] = {0}, *rbytes = &bytes[8];
  uint16_t value;

  uint8_t size = 0, octets = 0, symbols = 0;
  int8_t range = -1;

  bool breaked = false, inetv4 = false;

  if (!string || !*string)
    return -1;
  if (*string == ':' && *++string != ':')
    return -1;

  for (;;) {
    if ((symbols && *(string-1) == ':' && *(string) == ':' && !*(string+1) && !breaked) || (*string == ':' && !breaked)) {
      string++, range = 0, breaked = true;
      continue;
    }

    for (symbols = 0, value = 0; symbols < 4 && *string && inetv6_hexadecimal(*string) >= 0; string++, symbols++)
      value = (uint16_t)(16*value+(uint16_t)inetv6_hexadecimal(*string));

    if (*string && *string == '.') {
      string -= symbols, inetv4 = true, rbytes -= 2, octets = (uint8_t)(octets+2u);
      break;
    }

    if ((*string && *string != ':') || (*string && !*(string+1) && *string == ':'))
      return -1;
    if (octets > 8 || symbols > 4)
      return -1;

    bytes[(size++) & 7] = (uint16_t)value;
    range = (int8_t)(range != -1 ? range+1 : -1), octets++;

    if (!*string)
      break;

    string++;
  }

  if (breaked && octets < 8) {
    for (value = 1; value <= range; value++) {
      rbytes[-value] = bytes[size-value];
      bytes[size-value] = 0;
    }

    breaked = false;
    octets = 8;
  }

  if (octets != 8 || (breaked && octets == 8))
    return -1;

  if (network)
    for (value = 0, size = 0; value < (inetv4 ? 6 : 8); value++) {
      network->u8[size++] = (uint8_t)((bytes[value] >> 0x08) & 0xFF);
      network->u8[size++] = (uint8_t)((bytes[value]) & 0xFF);
    }

  if (inetv4)
    return inetv4_parse((struct inetv4 *)&network->u8[size], string);

  return 1;
}

char *
inetv6_format(const struct inetv6 *network, char *string, size_t length) {
  static const char *const hexadecimal = "0123456789abcdef";

  char source[INETV6_STRLENGTH] = {0};
  char *format = (char *)source;

  int start = -1, end = -1, zeros = 0;
  int size, byte;

  bool skip;

  string_zero(source, sizeof(source));

  if (!memcmp(network, "\0\0\0\0\0\0\0\0\0\0\0\0", 12) && (network->u8[12] || network->u8[13])) { 
    string_write(format, "::", sizeof(source));
    format += 2;

    inetv4_format((struct inetv4 *)&network->u8[12], format, sizeof(source)-2);
  } else {
    for (size = 0; size < INETV6_SIZE; size++) {
      for (byte = size; byte < 16 && network->u8[byte] == 0; byte++);

      if (zeros < byte-size)
        start = size, end = byte, zeros = byte-size;
    }

    if (start != -1 && !(start % 2 == 0))
      start++;
    if (end != -1)
      end--;

    for (size = 0; size < INETV6_SIZE; size += 2) {
      if (zeros >= 4 && size == (uint8_t)start) {
        if (start == 0)
          *format++ = ':';

        while (size != (uint8_t)end)
          size++;
        *format++ = ':';

        if (size == 15)
          break;
        if (!(size % 2 == 0))
          size++;
      }

      skip = true;

      if ((byte = network->u8[size] >> 4) != 0) {
        *format++ = hexadecimal[byte];
        skip = false;
      }

      if (((byte = network->u8[size] & 0x0F) != 0 && skip) || !skip) {
        *format++ = hexadecimal[byte];
        skip = false;
      }

      if (((byte = network->u8[size+1] >> 4) != 0 && skip) || !skip)
        *format++ = hexadecimal[byte];

      byte = network->u8[size+1] & 0x0F;
      *format++ = hexadecimal[byte];

      if (size != 14)
        *format++ = ':';
    }
  }

  if (string)
    return (char *)memcpy(string, source, length);

  return string_new(source);
}

bool
inetv6_isunspecified(const struct inetv6 *network) {
  return !memcmp(network, &INETV6_ALL, INETV6_SIZE);
}

bool
inetv6_isloopback(const struct inetv6 *network) {
  return !memcmp(network, &INETV6_LOOPBACK, INETV6_SIZE);
}

bool
inetv6_ismulticast(const struct inetv6 *network) {
  return (network->u8[0] == 0xFF);
}

bool
inetv6_islinklocal(const struct inetv6 *network) {
  return (network->u8[0] == 0xFE && ((network->u8[1] & 0xC0) == 0x80));
}

bool
inetv6_issitelocal(const struct inetv6 *network) {
  return network->u8[0] == 0xFE && ((network->u8[1] & 0xC0) == 0xC0);
}

bool
inetv6_isglobal(const struct inetv6 *network) {
  return (network->u8[0] & 0xE0) == 0x20;
// return !inetv6_isunspecified(network) && !inetv6_isloopback(network) && !inetv6_islinklocal(network) && !inetv6_issitelocal(network) && !inetv6_ismulticast(network);
}

bool
inetv6_isv4mapped(const struct inetv6 *network) {
  return (network->u32[0] == 0x00 && network->u32[1] == 0x00 && network->u16[4] == 0x00 && network->u16[5] == 0xFFFF);
}

int
inetv6_compare(const struct inetv6 *network1, const struct inetv6 *network2) {
  uint8_t octet;

  for (octet = 0; octet < INETV6_SIZE/sizeof(uint16_t); octet++)
    if (network1->u16[octet] < network2->u16[octet])
      return -1;
    else if (network1->u16[octet] > network2->u16[octet])
      return 1;

  return 0;
}

int
inetv6_cidr(const char *cidr, uint8_t *prefix_length, struct inetv6 *network, struct inetv6 *netmask) {
  char string[INETV6_STRLENGTH+1] = {0};

  uint8_t netmasku8[INETV6_SIZE] = {0};
  struct inetv6 addr = {0};

  uint8_t prefix;
  uint8_t size;

  if (sscanf(cidr, "%46[^/]/%" SCNu8, string, &prefix) != 2)
    return -1;
  if (prefix > 128)
    return -1;

  if (inetv6_parse(&addr, string) == -1)
    return -1;

  if (prefix_length)
    *prefix_length = prefix;

  for (size = 0; size < INETV6_SIZE; size++)
    if (prefix >= 8)
      netmasku8[size] = 0xFF, prefix -= 8;
    else if (prefix > 0)
      netmasku8[size] = (uint8_t)(0xFF << (8 - prefix)), prefix = 0;

  if (netmask)
    memcpy(netmask, netmasku8, INETV6_SIZE);

  if (network)
    for (size = 0; size < INETV6_SIZE; size++)
      network->u8[size] = addr.u8[size] & netmasku8[size];

  return 1;
}

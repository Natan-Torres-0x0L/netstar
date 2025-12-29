# @ netstar-build-target-system-uname
SYSTEM_UNAME = $(if $(strip $(OS)),$(OS),$(shell uname -s))

# @ netstar-build-target-system
SYSTEM ?= $(if $(filter $(SYSTEM_UNAME),Windows_NT), \
            windows,                                 \
          $(if $(filter $(SYSTEM_UNAME),Linux),      \
            linux,                                   \
          $(if $(filter $(SYSTEM_UNAME),Darwin),     \
            darwin,                                  \
          $(if $(filter $(SYSTEM_UNAME),FreeBSD),    \
            bsd,                                     \
          $(if $(filter $(SYSTEM_UNAME),OpenBSD),    \
            bsd,                                     \
          $(if $(filter $(SYSTEM_UNAME),NetBSD),     \
            bsd,                                     \
          $(if $(filter $(SYSTEM_UNAME),DragonFly),  \
            bsd)))))))

SYSTEM := $(strip $(SYSTEM))

SYSTEM_ARCH ?= x32

# @ netstar-build-target-is-specified
$(if $(filter $(SYSTEM),), \
  $(error target system/platform not specified/defined))

# @ netstar-build-target-is-supported
$(if $(filter $(SYSTEM),windows),,    \
  $(if $(filter $(SYSTEM),linux),,    \
    $(if $(filter $(SYSTEM),darwin),, \
      $(if $(filter $(SYSTEM),bsd),,  \
        $(error $(SYSTEM) system/platform not supported)))))

#
# @ Netstar external libraries directory
#

LIB := lib

#
# @ Netstar source directory
#

SRC := src

#
# @ Netstar extended source directory
#
# EXTENDED := $(SRC)/netstar-extended

#
# @ Netstar build directory
#

BUILD := build

#
# @ C compiler flags
#

CVERSION ?= -std=c11
CC ?= gcc

CDEFS := $(if $(NETSTAR_EXTENDED),-DNETSTAR_EXTENDED) -DNETSTAR_COLORED

CINCLUDE := $(if $(filter $(SYSTEM),windows),           \
              -I$(LIB)/network/netpacket/npcap/include) \
            -I$(LIB)                                    \
            -I$(SRC)

LDLIBS := $(if $(filter $(SYSTEM),windows),                     \
            -L$(LIB)/network/netpacket/npcap/lib/$(SYSTEM_ARCH) \
            -lpacket    \
            -lwpcap     \
            -lws2_32    \
            -lntdll     \
            -lmswsock   \
            -liphlpapi  \
            -lsetupapi  \
            -lcfgmgr32)
LDLIBS += -lm -pthread

CWFLAGS := -Wdeclaration-after-statement \
           -Wnested-externs              \
           -Wformat                      \
           -Winline                      \
           -Wno-switch
         # -Wmissing-prototypes -Wstrict-prototypes

CFLAGS += -O4 $(CDEFS) $(CINCLUDE) $(CWFLAGS) -fno-stack-protector -fno-common # -march=native

#
# @ ld compiler linker flags
#

LDFLAGS ?= $(if $(NETSTAR_EXTENDED),-Wl$(,)-rpath$(,)./build/netstar-extended)

#
# @ release binary strip configuration sections/flags
#

STRIP ?= strip
STRIPFLAGS := --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note \
              --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr \
              --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr      \
              --remove-section=.eh_frame_hdr

#
# @ release binary
#

define netstar_release_binary
  $(1)$(if $(filter $(SYSTEM),windows),.exe)
endef

RELEASE := $(call netstar_release_binary,release/netstar)
MAIN ?= $(SRC)/netstar-main.c


define netstar_build_sources_macro
  SOURCES += $(1)
endef

define netstar_build_sources
  $(eval $(call netstar_build_sources_macro,$(1),$(2)))
endef


# @ lib/collections
$(call netstar_build_sources,$(LIB)/collections/hashmap/hashmap.c)
$(call netstar_build_sources,$(LIB)/collections/hashset/hashset.c)
$(call netstar_build_sources,$(LIB)/collections/list/list.c)
$(call netstar_build_sources,$(LIB)/collections/map/map.c)
$(call netstar_build_sources,$(LIB)/collections/queue/queue.c)
$(call netstar_build_sources,$(LIB)/collections/rbtree/rbtree.c)
$(call netstar_build_sources,$(LIB)/collections/set/set.c)
$(call netstar_build_sources,$(LIB)/collections/collections-cycle.c)
$(call netstar_build_sources,$(LIB)/collections/collections.c)

# @ lib/network/netpacket
$(call netstar_build_sources,                      \
  $(if $(filter $(SYSTEM),windows),                \
    $(LIB)/network/netpacket/netpacket-windows.c,  \
  $(if $(filter $(SYSTEM),darwin),                 \
    $(LIB)/network/netpacket/netpacket-darwin.c,   \
  $(if $(filter $(SYSTEM),bsd),                    \
    $(LIB)/network/netpacket/netpacket-bsd.c,      \
  $(if $(filter $(SYSTEM),linux),                  \
    $(LIB)/network/netpacket/netpacket-linux.c)))) \
)
$(call netstar_build_sources,$(LIB)/network/netpacket/netpacket-errors.c)
$(call netstar_build_sources,$(LIB)/network/netpacket/netpacket.c)

# @ lib/network/netlink
$(call netstar_build_sources,                  \
  $(if $(filter $(SYSTEM),windows),            \
    $(LIB)/network/netlink/netlink-windows.c,  \
  $(if $(filter $(SYSTEM),darwin),             \
    $(LIB)/network/netlink/netlink-darwin.c,   \
  $(if $(filter $(SYSTEM),bsd),                \
    $(LIB)/network/netlink/netlink-bsd.c,      \
  $(if $(filter $(SYSTEM),linux),              \
    $(LIB)/network/netlink/netlink-linux.c)))) \
)
$(call netstar_build_sources,$(LIB)/network/netlink/netlink-errors.c)
$(call netstar_build_sources,$(LIB)/network/netlink/netlink.c)

# @ lib/network/macieee802
$(call netstar_build_sources,$(LIB)/network/macieee802/macieee802.c)

# @ lib/network/inet
$(call netstar_build_sources,$(LIB)/network/inet/inet-v4.c)
$(call netstar_build_sources,$(LIB)/network/inet/inet-v6.c)
$(call netstar_build_sources,$(LIB)/network/inet/inet.c)

# @ lib/network
$(call netstar_build_sources,$(LIB)/network/network-endpoint.c)
# $(call netstar_build_sources,$(LIB)/network/network-sockets.c)
# $(call netstar_build_sources,$(LIB)/network/network-tcp.c)
# $(call netstar_build_sources,$(LIB)/network/network-udp.c)
$(call netstar_build_sources,$(LIB)/network/network.c)

# @ lib/network/sockets
$(call netstar_build_sources,                 \
  $(if $(filter $(SYSTEM),windows),           \
    $(LIB)/network/sockets/sockets-windows.c, \
    $(LIB)/network/sockets/sockets-unix.c)    \
)
$(call netstar_build_sources,$(LIB)/network/sockets/sockets-select-reactor.c)
$(call netstar_build_sources,$(LIB)/network/sockets/sockets-poll-reactor.c)
$(call netstar_build_sources,$(LIB)/network/sockets/sockets-reactor-interrupter.c)
$(call netstar_build_sources,                          \
  $(if $(filter $(SYSTEM),windows),                    \
    $(LIB)/network/sockets/sockets-afd-reactor.c,      \
  $(if $(filter $(SYSTEM),darwin),                     \
    $(LIB)/network/sockets/sockets-kqueue-reactor.c,   \
  $(if $(filter $(SYSTEM),bsd),                        \
    $(LIB)/network/sockets/sockets-kqueue-reactor.c,   \
  $(if $(filter $(SYSTEM),linux),                      \
    $(LIB)/network/sockets/sockets-epoll-reactor.c)))) \
)

$(call netstar_build_sources,$(LIB)/network/sockets/sockets-options.c)
$(call netstar_build_sources,$(LIB)/network/sockets/sockets-handler.c)
$(call netstar_build_sources,$(LIB)/network/sockets/sockets-events.c)
$(call netstar_build_sources,$(LIB)/network/sockets/sockets-errors.c)
$(call netstar_build_sources,$(LIB)/network/sockets/sockets.c)

# @ lib/network/dns
$(call netstar_build_sources,$(LIB)/network/dns/dns.c)

# @ lib/network/resolv
$(call netstar_build_sources,$(LIB)/network/resolv/resolv-errors.c)
# $(call netstar_build_sources,$(LIB)/network/resolv/resolv-cache.c)
$(call netstar_build_sources,$(LIB)/network/resolv/resolv.c)

# @ lib/network/iana
$(call netstar_build_sources,$(LIB)/network/iana/iana.c)

# @ lib/buffers
$(call netstar_build_sources,$(LIB)/buffers/buffers.c)

# @ lib/strings
$(call netstar_build_sources,$(LIB)/strings/strings.c)

# @ lib/random
$(call netstar_build_sources,$(LIB)/random/random.c)

# @ lib/fnv1a
$(call netstar_build_sources,$(LIB)/fnv1a/fnv1a.c)

# @ lib/system
$(call netstar_build_sources,$(LIB)/system/system-errors.c)
$(call netstar_build_sources,$(LIB)/system/system.c)

# @ lib/console/colored
# $(call netstar_build_sources,$(LIB)/console/colored/colored-palette.c)
$(call netstar_build_sources,$(LIB)/console/colored/colored.c)

# @ lib/console/arguments
$(call netstar_build_sources,$(LIB)/console/arguments/arguments.c)

# @ lib/console
$(call netstar_build_sources,         \
  $(if $(filter $(SYSTEM),windows),   \
    $(LIB)/console/console-windows.c, \
    $(LIB)/console/console-unix.c)    \
)
$(call netstar_build_sources,$(LIB)/console/console.c)

#
# @ netstar
#

$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-dissectors.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-ethernet.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-arp.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-ipv4.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-ipv6.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-igmp.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-gre.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-icmpv4.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-icmpv6.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-tcp.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-udp.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-http.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-dns.c)
$(call netstar_build_sources,$(SRC)/netstar-dissectors/netstar-mdns.c)

ifdef NETSTAR_EXTENDED
$(call netstar_build_sources,$(EXTENDED)/netstar-ssl-downgrade.c)
endif

$(call netstar_build_sources,$(SRC)/netstar-arp-spoofing.c)
$(call netstar_build_sources,$(SRC)/netstar-ndp-spoofing.c)

$(call netstar_build_sources,$(SRC)/netstar-dns-spoofing.c)

$(call netstar_build_sources,$(SRC)/netstar-stealth.c)

$(call netstar_build_sources,$(SRC)/netstar-monitor.c)
$(call netstar_build_sources,$(SRC)/netstar-filter.c)

$(call netstar_build_sources,$(SRC)/netstar-scanner.c)
$(call netstar_build_sources,$(SRC)/netstar-recon.c)

$(call netstar_build_sources,$(SRC)/netstar-redirect.c)

ifdef NETSTAR_EXTENDED
$(call netstar_build_sources,$(EXTENDED)/netstar-http-server.c)
else
$(call netstar_build_sources,$(SRC)/netstar-http-server.c)
endif

$(call netstar_build_sources,$(SRC)/netstar-terminate.c)

$(call netstar_build_sources,$(SRC)/netstar-format.c)
$(call netstar_build_sources,$(SRC)/netstar-log.c)
$(call netstar_build_sources,$(SRC)/netstar-colored.c)

$(call netstar_build_sources,$(SRC)/netstar-time.c)

$(call netstar_build_sources,$(SRC)/netstar-vendors.c)
$(call netstar_build_sources,$(SRC)/netstar-hosts.c)

$(call netstar_build_sources,$(SRC)/netstar-capture.c)
$(call netstar_build_sources,$(SRC)/netstar-forward.c)

$(call netstar_build_sources,$(SRC)/netstar-threads.c)

$(call netstar_build_sources,$(SRC)/netstar-packet.c)
$(call netstar_build_sources,$(SRC)/netstar-utils.c)

$(call netstar_build_sources,$(SRC)/netstar-commands.c)
$(call netstar_build_sources,$(SRC)/netstar-services.c)

$(call netstar_build_sources,$(SRC)/netstar.c)
$(call netstar_build_sources,$(MAIN))


# @ netstar-build-source-dependencie
define netstar_build_source_dependency
  $(patsubst $(firstword $(subst /, ,$(1)))/%.c,$(BUILD)/%.d,$(1))
endef

NETSTAR_SOURCES_DEPENDECIES = $(foreach src,$(SOURCES),    \
                                $(if $(filter %.c,$(src)), \
                                  $(call netstar_build_source_dependency,$(src))))

# @ netstar-build-source-objects
define netstar_build_source_object
  $(patsubst $(firstword $(subst /, ,$(1)))/%.c,$(BUILD)/%.o,$(1))
endef

define netstar_build_source_directory
  $(dir $(patsubst $(firstword $(subst /, ,$(1)))/%.c,$(BUILD)/%.o,$(1)))
endef

NETSTAR_SOURCES_OBJECTS += $(foreach src,$(SOURCES),    \
                             $(if $(filter %.c,$(src)), \
                               $(call netstar_build_source_object,$(src))))

# @ netstar-build-compile-release
$(RELEASE): $(NETSTAR_SOURCES_OBJECTS)
	$(call netstar_build_make_directory,$(RELEASE))
	$(CC) $(CVERSION) $(LDFLAGS) $(CFLAGS) -MMD -MP -o $@ $^ $(LDLIBS)
  # $(STRIP) $(RELEASE) -S --strip-unneeded # $(STRIPFLAGS)

# @ netstar-build-sources
-include $(NETSTAR_SOURCES_DEPENDECIES)

define netstar_build_make_directory
$(if $(filter $(SYSTEM),windows), \
  @cmd /C if not exist "$(subst,/,\,$(dir $(1)))" mkdir "$(subst,/,\,$(dir $(1)))", \
  @mkdir -p $(dir $(1)))
endef

define netstar_build_compile_object
$(1): $(2)
	$(call netstar_build_make_directory,$(1))
	$(CC) $(CVERSION) $(CFLAGS) -fPIC -MMD -MP -MF $(3) -c $$< -o $$@
endef

# @ netstar-build-compile-dependency-rules
$(foreach src,$(SOURCES),                              \
  $(eval $(call netstar_build_compile_object,          \
           $(call netstar_build_source_object,$(src)), \
           $(src),                                     \
           $(call netstar_build_source_dependency,$(src)))))

# @ netstar-clean-rules
define netstar_build_objects_clean
$(if $(filter $(SYSTEM),windows),                          \
	@for /r build %%f in (*.o *.o.* *.d *.dll) do del "%%f", \
	@find build -type f \( -name "*.o" -o -name "*.o.*" -o -name "*.d" -o -name "*.so" -o -name "*.dll" \) -delete)
endef

.PHONY: build-clean clean
build-clean clean:
	$(call netstar_build_objects_clean)

define netstar_build_release_clean
$(if $(filter $(SYSTEM),windows), \
	@del $(RELEASE),                \
	@rm -f $(RELEASE))
endef

.PHONY: build-clean-all clean-all
build-clean-all clean-all:
	$(call netstar_build_release_clean)
	$(call netstar_build_objects_clean)

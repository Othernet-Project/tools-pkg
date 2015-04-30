TOP_DIR := $(shell pwd)
-include $(TOP_DIR)/../Makefile.in

CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
STRIP	= $(CROSS_COMPILE)strip
CFLAGS  += -Wall -DLINUX
LIBS	 = -lstdc++ -lcrypto

HOSTCC	 	= gcc
HOSTLD		= ld
HOSTCFLAGS  = -Wall -DLINUX
HOSTLIBS 	= -lstdc++ -lcrypto
DEL_FILE 	= rm -f

HEADERS	 = $(wildcard *.h )

TARGETS  = pkgtool mkpkg

.PHONY: install clean debug release

first: debug

debug: CFLAGS += -ggdb
debug: HOSTCFLAGS += -ggdb
release: CFLAGS += -O2
release: HOSTCFLAGS += -O2

debug release: $(TARGETS)

mkpkg: mkpkg.cpp installer.o $(HEADERS)
	@rm -f $@
	$(HOSTCC) $(HOSTCFLAGS) -o $@ mkpkg.cpp installer.o $(HOSTLIBS)

pkgtool: pkgtool.cpp $(HEADERS)
	@rm -f $@
	$(CC) $(CFLAGS) -o $@ pkgtool.cpp $(LIBS)

installer.o: installer.cpp $(HEADERS)
	@rm -f $@
	$(CC) $(CFLAGS) -o installer.bin installer.cpp -static $(LIBS)
	$(STRIP) installer.bin
	$(HOSTLD) -r -b binary -o $@ installer.bin

clean:
	$(DEL_FILE) $(TARGETS) installer.bin installer.o

install: $(TARGETS)
	@mkdir -p $(STAGING_DIR)/sbin
	install -m 0755 pkgtool $(TARGET_DIR)/usr/sbin
	@mkdir -p $(HOST_DIR)/usr/bin
	install -m 0755 mkpkg $(HOST_DIR)/usr/bin

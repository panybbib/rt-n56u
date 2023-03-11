SRC_NAME = aliyundrive-webdav
THISDIR = $(shell pwd)

all:

config_test:

configure:

clean:

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/aliyundrive-webdav.sh /usr/bin/aliyundrive-webdav.sh
	$(ROMFSINST) /etc_ro/aliyundrive_script.sh
ifeq ($(CONFIG_FIRMWARE_INCLUDE_ALDRIVERBIN),y)
	$(ROMFSINST) -p +x $(THISDIR)/aliyundrive-webdav /usr/bin/aliyundrive-webdav
endif

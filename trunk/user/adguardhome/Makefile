THISDIR = $(shell pwd)
all:

clean:

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/adguardhome.sh /usr/bin/adguardhome.sh
	$(ROMFSINST) /etc_ro/adguardhome_script.sh
	$(ROMFSINST) /etc_ro/adg.sh
	#ifeq ($(CONFIG_FIRMWARE_INCLUDE_ADGUARDBIN),y)
	#$(ROMFSINST) -p +x $(THISDIR)/AdGuardHome /usr/bin/AdGuardHome
	#endif

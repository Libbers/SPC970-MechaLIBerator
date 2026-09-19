EE_BIN = SPC970-MechaLIBerator.elf
EE_OBJS = spc970_rom_dumper.o session_store.o usb_storage.o usbd_irx.o usbhdfsd_irx.o
EE_LIBS = -ldebug -lcdvd -lpatches -lpad
EE_WARNFLAGS = -Wall -Wextra
EE_DBGINFOFLAGS =
EE_CFLAGS += -ffunction-sections -fdata-sections
EE_LDFLAGS += -Wl,--gc-sections

.PHONY: all clean

all: $(EE_BIN)
	$(EE_STRIP) --strip-unneeded -R .mdebug.eabi64 -R .reginfo -R .comment $(EE_BIN)

spc970_rom_dumper.o session_store.o usb_storage.o: usb_storage.h
spc970_rom_dumper.o: restore_report.h capture_slot.h
spc970_rom_dumper.o session_store.o: session_store.h

%_irx.c:
	$(PS2SDK)/bin/bin2c $(PS2SDK)/iop/irx/$*.irx $@ $*_irx

clean:
	rm -rf $(EE_BIN) $(EE_OBJS) usbd_irx.c usbhdfsd_irx.c obj *.map

include $(PS2SDK)/samples/Makefile.pref
include $(PS2SDK)/samples/Makefile.eeglobal

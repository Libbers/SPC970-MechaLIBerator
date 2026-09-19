#ifndef CAPTURE_SLOT_H
#define CAPTURE_SLOT_H

#include <stdio.h>
#include "usb_storage.h"

enum capture_slot_error {
    CAPTURE_SLOTS_FULL = -1,
    CAPTURE_PATH_TOO_LONG = -2
};

static int find_capture_slot(const char *directory)
{
    static const char *const stems[] = {"NVRAM", "NVRAM", "PROBE", "NVRAM"};
    static const char *const suffixes[] = {".BIN", "_RESTORE.BIN", ".BIN", ".TXT"};
    char path[128];
    int slot;

    for (slot = 0; slot < 100; slot++) {
        int kind;
        int occupied = 0;

        for (kind = 0; kind < 4; kind++) {
            int length = snprintf(path, sizeof(path), "%s/%s%02d%s",
                                  directory, stems[kind], slot, suffixes[kind]);
            if (length < 0 || length >= (int)sizeof(path))
                return CAPTURE_PATH_TOO_LONG;
            occupied |= file_exists(path);
        }
        if (!occupied)
            return slot;
    }
    return CAPTURE_SLOTS_FULL;
}

#endif

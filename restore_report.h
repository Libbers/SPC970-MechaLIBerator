#ifndef RESTORE_REPORT_H
#define RESTORE_REPORT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct restore_report_fields {
    uint8_t version[4];
    uint32_t crc;
    char model[20];
    char filename[12];
};

static int report_hex_value(unsigned char character)
{
    if (character >= '0' && character <= '9')
        return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
    return -1;
}

static int report_key_matches(const char *key, size_t length,
                              const char *expected)
{
    return length == strlen(expected) && memcmp(key, expected, length) == 0;
}

static int report_parse_version(const char *value, size_t length,
                                uint8_t version[4])
{
    size_t offset = 0;
    int index;

    if (length > 32)
        return 0;
    for (index = 0; index < 4; index++) {
        int high;
        int low;

        while (offset < length &&
               (value[offset] == ' ' || value[offset] == '\t'))
            offset++;
        if (length - offset < 2)
            return 0;
        high = report_hex_value((unsigned char)value[offset]);
        low = report_hex_value((unsigned char)value[offset + 1]);
        if (high < 0 || low < 0)
            return 0;
        version[index] = (uint8_t)((high << 4) | low);
        offset += 2;
    }
    while (offset < length &&
           (value[offset] == ' ' || value[offset] == '\t'))
        offset++;
    return offset == length;
}

static int parse_restore_report(const char *text, size_t length,
                                struct restore_report_fields *result)
{
    struct restore_report_fields parsed = {{0}, 0, {0}, {0}};
    unsigned int seen = 0;
    size_t offset = 0;

    if (!text || !result || length == 0 || length >= 4096)
        return 0;
    while (offset < length) {
        const char *line = text + offset;
        const char *newline = memchr(line, '\n', length - offset);
        const char *separator;
        const char *key;
        const char *value;
        size_t line_length;
        size_t key_length;
        size_t value_length;
        size_t index;
        unsigned int field = 0;

        /* Require a complete line, including its terminator. */
        if (!newline)
            return 0;
        line_length = (size_t)(newline - line);
        offset += line_length + 1;
        if (line_length && line[line_length - 1] == '\r')
            line_length--;
        for (index = 0; index < line_length; index++) {
            unsigned char character = (unsigned char)line[index];
            if ((character < 0x20 && character != '\t') || character > 0x7e)
                return 0;
        }
        separator = memchr(line, '=', line_length);
        key = line;
        key_length = separator ? (size_t)(separator - line) : line_length;
        while (key_length && (*key == ' ' || *key == '\t')) {
            key++;
            key_length--;
        }
        while (key_length &&
               (key[key_length - 1] == ' ' || key[key_length - 1] == '\t'))
            key_length--;
        if (report_key_matches(key, key_length, "raw_scmd_03_00"))
            field = 1;
        else if (report_key_matches(key, key_length, "nvram_crc32") ||
                 report_key_matches(key, key_length, "crc32"))
            field = 2;
        else if (report_key_matches(key, key_length, "console_model") ||
                 report_key_matches(key, key_length, "reported_console"))
            field = 4;
        else if (report_key_matches(key, key_length, "nvram_file") ||
                 report_key_matches(key, key_length, "file"))
            field = 8;
        if (!field)
            continue;
        if (!separator || key != line ||
            key_length != (size_t)(separator - line) || (seen & field))
            return 0;
        seen |= field;
        value = separator + 1;
        value_length = line_length - (size_t)(value - line);
        if (field == 1) {
            if (!report_parse_version(value, value_length, parsed.version))
                return 0;
        } else if (field == 2) {
            if (value_length != 8)
                return 0;
            for (index = 0; index < value_length; index++) {
                int digit = report_hex_value((unsigned char)value[index]);
                if (digit < 0)
                    return 0;
                parsed.crc = (parsed.crc << 4) | (uint32_t)digit;
            }
        } else if (field == 4) {
            int visible = 0;
            if (!value_length || value_length >= sizeof(parsed.model))
                return 0;
            for (index = 0; index < value_length; index++) {
                if ((unsigned char)value[index] < 0x20)
                    return 0;
                visible |= value[index] != ' ';
            }
            if (!visible)
                return 0;
            memcpy(parsed.model, value, value_length);
        } else {
            if (value_length != 11 || memcmp(value, "NVRAM", 5) != 0 ||
                value[5] < '0' || value[5] > '9' ||
                value[6] < '0' || value[6] > '9' ||
                memcmp(value + 7, ".BIN", 4) != 0)
                return 0;
            memcpy(parsed.filename, value, value_length);
        }
    }
    if (seen != 15)
        return 0;
    *result = parsed;
    return 1;
}

#endif

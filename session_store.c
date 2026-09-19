#include "session_store.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "usb_storage.h"

static const uint8_t map_magic[8] = {
    'S', 'P', 'C', '9', '7', '0', 'M', '2'
};
static const uint8_t nvram_magic[8] = {
    'S', 'P', 'C', '9', '7', '0', 'N', '2'
};
static const uint8_t legacy_map_magic[11] = {
    'S', 'P', 'C', '9', '7', '0', 'R', 'O', 'M', 'L', 'E'
};
static const uint8_t legacy_nvram_magic[8] = {
    'S', 'P', 'C', '9', '7', '0', 'N', 'V'
};

static void put_u32le(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static uint32_t get_u32le(const uint8_t *input)
{
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

uint32_t session_crc32(const void *data, int size)
{
    const uint8_t *bytes = data;
    uint32_t crc = UINT32_C(0xffffffff);
    int byte;

    if (!data || size < 0)
        return 0;
    while (size-- > 0) {
        crc ^= *bytes++;
        for (byte = 0; byte < 8; byte++)
            crc = (crc >> 1) ^
                  (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(crc & 1));
    }
    return ~crc;
}

const char *session_state_name(enum session_state state)
{
    switch (state) {
        case SESSION_NO_SESSION:
            return "no-session";
        case SESSION_VALID_SESSION:
            return "valid-session";
        case SESSION_INCOMPLETE_FILES:
            return "incomplete-files";
        case SESSION_INCOMPATIBLE_FORMAT:
            return "incompatible-format";
        case SESSION_CORRUPT_METADATA:
            return "corrupt-metadata";
        case SESSION_MIXED_FILES:
            return "mixed-session-files";
        case SESSION_DIFFERENT_CONSOLE:
            return "different-console";
        case SESSION_AMBIGUOUS_SESSIONS:
            return "ambiguous-sessions";
        case SESSION_SLOTS_FULL:
            return "session-slots-full";
        case SESSION_CORRUPT_ROM_CHUNKS:
            return "corrupt-rom-chunks";
    }
    return "corrupt-metadata";
}

static void build_common_header(uint8_t *output, const uint8_t magic[8],
                                const uint8_t id[SESSION_ID_SIZE])
{
    memset(output, 0, SESSION_MAP_HEADER_SIZE);
    memcpy(output, magic, 8);
    put_u32le(output + 8, SESSION_FORMAT_VERSION);
    put_u32le(output + 12, SESSION_MAP_HEADER_SIZE);
    memcpy(output + 16, id, SESSION_ID_SIZE);
}

void session_build_nvram_file(uint8_t output[SESSION_NVRAM_FILE_SIZE],
                              const struct session_profile *profile,
                              const uint8_t id[SESSION_ID_SIZE],
                              const uint8_t baseline[SESSION_NVRAM_SIZE])
{
    build_common_header(output, nvram_magic, id);
    put_u32le(output + 32, session_crc32(baseline, SESSION_NVRAM_SIZE));
    put_u32le(output + 36, profile->rom_start);
    put_u32le(output + 40, SESSION_ROM_SIZE);
    put_u32le(output + 44, profile->layout_signature);
    memcpy(output + 48, profile->raw_version, SESSION_RAW_VERSION_SIZE);
    put_u32le(output + 52, session_crc32(output, 52));
    memcpy(output + SESSION_NVRAM_HEADER_SIZE, baseline, SESSION_NVRAM_SIZE);
}

void session_build_map_file(uint8_t output[SESSION_MAP_FILE_SIZE],
                            const struct session_profile *profile,
                            const uint8_t id[SESSION_ID_SIZE],
                            uint32_t baseline_crc)
{
    memset(output, 0, SESSION_MAP_FILE_SIZE);
    build_common_header(output, map_magic, id);
    put_u32le(output + 32, profile->rom_start);
    put_u32le(output + 36, SESSION_ROM_SIZE);
    put_u32le(output + 40, SESSION_CHUNK_SIZE);
    put_u32le(output + 44, SESSION_CHUNK_COUNT);
    put_u32le(output + 48, baseline_crc);
    put_u32le(output + 52, profile->layout_signature);
    memcpy(output + 56, profile->raw_version, SESSION_RAW_VERSION_SIZE);
    put_u32le(output + 60, session_crc32(output, 60));
}

enum header_kind {
    HEADER_CURRENT,
    HEADER_INCOMPATIBLE,
    HEADER_TRUNCATED,
    HEADER_CORRUPT
};

static enum header_kind header_kind(const char *path, int map)
{
    uint8_t header[16];

    if (!read_file_range(path, 0, header, sizeof(header)))
        return HEADER_TRUNCATED;
    if (memcmp(header, map ? map_magic : nvram_magic, 8) == 0)
        return get_u32le(header + 8) == SESSION_FORMAT_VERSION ?
               HEADER_CURRENT : HEADER_INCOMPATIBLE;
    if ((map && memcmp(header, legacy_map_magic,
                       sizeof(legacy_map_magic)) == 0) ||
        (!map && memcmp(header, legacy_nvram_magic,
                        sizeof(legacy_nvram_magic)) == 0))
        return HEADER_INCOMPATIBLE;
    return HEADER_CORRUPT;
}

static int nvram_header_valid(const uint8_t header[SESSION_NVRAM_HEADER_SIZE])
{
    static const uint8_t zero[8] = {0};

    return memcmp(header, nvram_magic, 8) == 0 &&
           get_u32le(header + 8) == SESSION_FORMAT_VERSION &&
           get_u32le(header + 12) == SESSION_NVRAM_HEADER_SIZE &&
           get_u32le(header + 52) == session_crc32(header, 52) &&
           memcmp(header + 56, zero, sizeof(zero)) == 0;
}

static int map_header_valid(const uint8_t header[SESSION_MAP_HEADER_SIZE])
{
    return memcmp(header, map_magic, 8) == 0 &&
           get_u32le(header + 8) == SESSION_FORMAT_VERSION &&
           get_u32le(header + 12) == SESSION_MAP_HEADER_SIZE &&
           get_u32le(header + 60) == session_crc32(header, 60);
}

int session_load_current_baseline(const char *path,
                                  const struct session_profile *profile,
                                  struct session_snapshot *snapshot)
{
    uint8_t header[SESSION_NVRAM_HEADER_SIZE];

    if (!path || !profile || !snapshot ||
        !file_has_size(path, SESSION_NVRAM_FILE_SIZE) ||
        !read_file_range(path, 0, header, sizeof(header)) ||
        !nvram_header_valid(header) ||
        !read_file_range(path, SESSION_NVRAM_HEADER_SIZE,
                         snapshot->baseline, SESSION_NVRAM_SIZE) ||
        get_u32le(header + 32) !=
            session_crc32(snapshot->baseline, SESSION_NVRAM_SIZE) ||
        get_u32le(header + 36) != profile->rom_start ||
        get_u32le(header + 40) != SESSION_ROM_SIZE ||
        get_u32le(header + 44) != profile->layout_signature ||
        memcmp(header + 48, profile->raw_version,
               SESSION_RAW_VERSION_SIZE) != 0)
        return 0;
    memcpy(snapshot->id, header + 16, SESSION_ID_SIZE);
    return 1;
}

enum session_baseline_state session_inspect_baseline(
    const char *path, const struct session_profile *profile,
    struct session_snapshot *snapshot)
{
    uint8_t header[SESSION_NVRAM_HEADER_SIZE];
    enum header_kind kind;

    if (!path || !profile || !snapshot || !file_exists(path))
        return SESSION_BASELINE_INCOMPLETE;
    kind = header_kind(path, 0);
    if (kind == HEADER_INCOMPATIBLE)
        return SESSION_BASELINE_INCOMPATIBLE;
    if (kind == HEADER_TRUNCATED ||
        !file_has_size(path, SESSION_NVRAM_FILE_SIZE))
        return SESSION_BASELINE_INCOMPLETE;
    if (kind != HEADER_CURRENT ||
        !read_file_range(path, 0, header, sizeof(header)) ||
        !nvram_header_valid(header) ||
        !read_file_range(path, SESSION_NVRAM_HEADER_SIZE,
                         snapshot->baseline, SESSION_NVRAM_SIZE) ||
        get_u32le(header + 32) !=
            session_crc32(snapshot->baseline, SESSION_NVRAM_SIZE))
        return SESSION_BASELINE_CORRUPT;
    memcpy(snapshot->id, header + 16, SESSION_ID_SIZE);
    if (get_u32le(header + 36) != profile->rom_start ||
        get_u32le(header + 40) != SESSION_ROM_SIZE)
        return SESSION_BASELINE_INCOMPATIBLE;
    if (get_u32le(header + 44) != profile->layout_signature ||
        memcmp(header + 48, profile->raw_version,
               SESSION_RAW_VERSION_SIZE) != 0)
        return SESSION_BASELINE_DIFFERENT_CONSOLE;
    return SESSION_BASELINE_VALID;
}

enum session_state session_inspect(const struct session_paths *paths,
                                   const struct session_profile *profile,
                                   struct session_snapshot *snapshot)
{
    uint8_t map_header[SESSION_MAP_HEADER_SIZE];
    uint8_t nvram_header[SESSION_NVRAM_HEADER_SIZE];
    enum header_kind map_kind;
    enum header_kind nvram_kind;
    uint32_t baseline_crc;
    int exists[3];
    int found_gap = 0;
    int rom_descriptor;
    int chunk;

    if (!paths || !profile || !snapshot)
        return SESSION_CORRUPT_METADATA;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->corrupt_chunk = -1;
    exists[0] = file_exists(paths->rom);
    exists[1] = file_exists(paths->map);
    exists[2] = file_exists(paths->nvram);
    if (!exists[0] && !exists[1] && !exists[2])
        return SESSION_NO_SESSION;
    if (!exists[0] || !exists[1] || !exists[2])
        return SESSION_INCOMPLETE_FILES;

    map_kind = header_kind(paths->map, 1);
    nvram_kind = header_kind(paths->nvram, 0);
    if (map_kind == HEADER_INCOMPATIBLE ||
        nvram_kind == HEADER_INCOMPATIBLE)
        return SESSION_INCOMPATIBLE_FORMAT;
    if (map_kind == HEADER_TRUNCATED || nvram_kind == HEADER_TRUNCATED)
        return SESSION_INCOMPLETE_FILES;
    if (map_kind != HEADER_CURRENT || nvram_kind != HEADER_CURRENT)
        return SESSION_CORRUPT_METADATA;
    if (!file_has_size(paths->rom, SESSION_ROM_SIZE) ||
        !file_has_size(paths->map, SESSION_MAP_FILE_SIZE) ||
        !file_has_size(paths->nvram, SESSION_NVRAM_FILE_SIZE))
        return SESSION_INCOMPLETE_FILES;
    if (!read_file_range(paths->map, 0, map_header, sizeof(map_header)) ||
        !read_file_range(paths->nvram, 0, nvram_header,
                         sizeof(nvram_header)) ||
        !map_header_valid(map_header) ||
        !nvram_header_valid(nvram_header))
        return SESSION_CORRUPT_METADATA;

    if (memcmp(map_header + 16, nvram_header + 16, SESSION_ID_SIZE) != 0 ||
        get_u32le(map_header + 32) != get_u32le(nvram_header + 36) ||
        get_u32le(map_header + 36) != get_u32le(nvram_header + 40) ||
        get_u32le(map_header + 48) != get_u32le(nvram_header + 32) ||
        get_u32le(map_header + 52) != get_u32le(nvram_header + 44) ||
        memcmp(map_header + 56, nvram_header + 48,
               SESSION_RAW_VERSION_SIZE) != 0)
        return SESSION_MIXED_FILES;
    if (get_u32le(map_header + 32) != profile->rom_start ||
        get_u32le(map_header + 36) != SESSION_ROM_SIZE ||
        get_u32le(map_header + 40) != SESSION_CHUNK_SIZE ||
        get_u32le(map_header + 44) != SESSION_CHUNK_COUNT)
        return SESSION_INCOMPATIBLE_FORMAT;
    if (get_u32le(map_header + 52) != profile->layout_signature ||
        memcmp(map_header + 56, profile->raw_version,
               SESSION_RAW_VERSION_SIZE) != 0)
        return SESSION_DIFFERENT_CONSOLE;

    memcpy(snapshot->id, map_header + 16, SESSION_ID_SIZE);
    if (!read_file_range(paths->nvram, SESSION_NVRAM_HEADER_SIZE,
                         snapshot->baseline, SESSION_NVRAM_SIZE))
        return SESSION_INCOMPLETE_FILES;
    baseline_crc = session_crc32(snapshot->baseline, SESSION_NVRAM_SIZE);
    if (baseline_crc != get_u32le(nvram_header + 32))
        return SESSION_CORRUPT_METADATA;
    if (!read_file_range(paths->map, SESSION_MAP_CRC_OFFSET,
                         snapshot->chunk_crc_le, SESSION_MAP_CRC_SIZE) ||
        !read_file_range(paths->map, SESSION_MAP_BITMAP_OFFSET,
                         snapshot->bitmap, SESSION_MAP_BITMAP_SIZE))
        return SESSION_INCOMPLETE_FILES;

    rom_descriptor = open(paths->rom, O_RDONLY);
    if (rom_descriptor < 0)
        return SESSION_INCOMPLETE_FILES;
    for (chunk = 0; chunk < SESSION_CHUNK_COUNT; chunk++) {
        uint8_t saved_chunk[SESSION_CHUNK_SIZE];
        int marked = (snapshot->bitmap[chunk >> 3] >> (chunk & 7)) & 1;

        if (!marked) {
            found_gap = 1;
            continue;
        }
        if (found_gap) {
            close(rom_descriptor);
            return SESSION_CORRUPT_METADATA;
        }
        if (!read_full(rom_descriptor, saved_chunk, sizeof(saved_chunk))) {
            close(rom_descriptor);
            return SESSION_INCOMPLETE_FILES;
        }
        if (session_crc32(saved_chunk, sizeof(saved_chunk)) !=
            get_u32le(snapshot->chunk_crc_le + chunk * 4)) {
            snapshot->corrupt_chunk = chunk;
            close(rom_descriptor);
            return SESSION_CORRUPT_ROM_CHUNKS;
        }
        snapshot->completed_chunks++;
    }
    if (close(rom_descriptor) < 0)
        return SESSION_INCOMPLETE_FILES;
    return SESSION_VALID_SESSION;
}

int session_raw_model_matches(const uint8_t *first, const uint8_t *second)
{
    return first && second &&
           memcmp(first + SESSION_RAW_MODEL_OFFSET,
                  second + SESSION_RAW_MODEL_OFFSET,
                  SESSION_RAW_MODEL_SIZE) == 0;
}

int session_matching_baseline_banks(const uint8_t *live,
                                    const uint8_t *baseline)
{
    int matching = 0;
    int bank;

    if (!live || !baseline)
        return 0;
    for (bank = 0; bank < SESSION_NVRAM_SIZE / SESSION_CHUNK_SIZE; bank++)
        matching += memcmp(live + bank * SESSION_CHUNK_SIZE,
                           baseline + bank * SESSION_CHUNK_SIZE,
                           SESSION_CHUNK_SIZE) == 0;
    return matching;
}

int session_recovery_words_match(const uint8_t *live,
                                 const uint8_t *baseline,
                                 const uint8_t *saved_banks,
                                 unsigned int saved_bank_mask,
                                 int ignored_bank)
{
    int bank;

    if (!live || !baseline || !saved_banks || ignored_bank < -1 ||
        ignored_bank >= SESSION_NVRAM_SIZE / SESSION_CHUNK_SIZE)
        return 0;
    for (bank = 0; bank < SESSION_NVRAM_SIZE / SESSION_CHUNK_SIZE; bank++) {
        int byte;
        if (bank == ignored_bank)
            continue;
        for (byte = 0; byte < SESSION_CHUNK_SIZE; byte += 2) {
            int offset = bank * SESSION_CHUNK_SIZE + byte;
            int baseline_match =
                live[offset] == baseline[offset] &&
                live[offset + 1] == baseline[offset + 1];
            int saved_match = (saved_bank_mask & (1u << bank)) &&
                live[offset] == saved_banks[offset + 1] &&
                live[offset + 1] == saved_banks[offset];
            if (!baseline_match && !saved_match)
                return 0;
        }
    }
    return 1;
}

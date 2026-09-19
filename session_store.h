#ifndef SESSION_STORE_H
#define SESSION_STORE_H

#include <stdint.h>

#define SESSION_FORMAT_VERSION 2u
#define SESSION_ID_SIZE 16
#define SESSION_RAW_VERSION_SIZE 4
#define SESSION_RAW_MODEL_OFFSET 0x1a0
#define SESSION_RAW_MODEL_SIZE 16
#define SESSION_NVRAM_SIZE 1024
#define SESSION_CHUNK_SIZE 256
#define SESSION_CHUNK_COUNT 1024
#define SESSION_ROM_SIZE (SESSION_CHUNK_SIZE * SESSION_CHUNK_COUNT)

#define SESSION_MAP_HEADER_SIZE 64
#define SESSION_MAP_CRC_OFFSET SESSION_MAP_HEADER_SIZE
#define SESSION_MAP_CRC_SIZE (SESSION_CHUNK_COUNT * 4)
#define SESSION_MAP_BITMAP_OFFSET (SESSION_MAP_CRC_OFFSET + SESSION_MAP_CRC_SIZE)
#define SESSION_MAP_BITMAP_SIZE (SESSION_CHUNK_COUNT / 8)
#define SESSION_MAP_FILE_SIZE (SESSION_MAP_BITMAP_OFFSET + SESSION_MAP_BITMAP_SIZE)

#define SESSION_NVRAM_HEADER_SIZE 64
#define SESSION_NVRAM_FILE_SIZE (SESSION_NVRAM_HEADER_SIZE + SESSION_NVRAM_SIZE)

enum session_state {
    SESSION_NO_SESSION,
    SESSION_VALID_SESSION,
    SESSION_INCOMPLETE_FILES,
    SESSION_INCOMPATIBLE_FORMAT,
    SESSION_CORRUPT_METADATA,
    SESSION_MIXED_FILES,
    SESSION_DIFFERENT_CONSOLE,
    SESSION_AMBIGUOUS_SESSIONS,
    SESSION_SLOTS_FULL,
    SESSION_CORRUPT_ROM_CHUNKS
};

enum session_baseline_state {
    SESSION_BASELINE_VALID,
    SESSION_BASELINE_DIFFERENT_CONSOLE,
    SESSION_BASELINE_INCOMPATIBLE,
    SESSION_BASELINE_INCOMPLETE,
    SESSION_BASELINE_CORRUPT
};

struct session_paths {
    const char *rom;
    const char *map;
    const char *nvram;
};

struct session_profile {
    uint32_t rom_start;
    uint32_t layout_signature;
    uint8_t raw_version[SESSION_RAW_VERSION_SIZE];
};

struct session_snapshot {
    uint8_t id[SESSION_ID_SIZE];
    uint8_t baseline[SESSION_NVRAM_SIZE];
    uint8_t chunk_crc_le[SESSION_MAP_CRC_SIZE];
    uint8_t bitmap[SESSION_MAP_BITMAP_SIZE];
    int completed_chunks;
    int corrupt_chunk;
};

uint32_t session_crc32(const void *data, int size);
const char *session_state_name(enum session_state state);
void session_build_nvram_file(uint8_t output[SESSION_NVRAM_FILE_SIZE],
                              const struct session_profile *profile,
                              const uint8_t id[SESSION_ID_SIZE],
                              const uint8_t baseline[SESSION_NVRAM_SIZE]);
void session_build_map_file(uint8_t output[SESSION_MAP_FILE_SIZE],
                            const struct session_profile *profile,
                            const uint8_t id[SESSION_ID_SIZE],
                            uint32_t baseline_crc);
enum session_state session_inspect(const struct session_paths *paths,
                                   const struct session_profile *profile,
                                   struct session_snapshot *snapshot);
int session_load_current_baseline(const char *path,
                                  const struct session_profile *profile,
                                  struct session_snapshot *snapshot);
enum session_baseline_state session_inspect_baseline(
    const char *path, const struct session_profile *profile,
    struct session_snapshot *snapshot);
int session_raw_model_matches(const uint8_t *first, const uint8_t *second);
int session_matching_baseline_banks(const uint8_t *live,
                                    const uint8_t *baseline);
int session_recovery_words_match(const uint8_t *live,
                                 const uint8_t *baseline,
                                 const uint8_t *saved_banks,
                                 unsigned int saved_bank_mask,
                                 int ignored_bank);

#endif

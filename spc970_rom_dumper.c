#include <debug.h>
#include <fcntl.h>
#include <kernel.h>
#include <libcdvd.h>
#include <libpad.h>
#include <loadfile.h>
#include <sifrpc.h>
#include <stdio.h>
#include <string.h>
#include <tamtypes.h>
#include <timer.h>
#include <unistd.h>

#include "usb_storage.h"
#include "restore_report.h"
#include "capture_slot.h"
#include "session_store.h"

#define BUILD_DATE              __DATE__
#define BUILD_TIME              __TIME__

#define PROJECT_NAME            "SPC970-MechaLIBerator"
#define TARGET_DUMP_STEM        "SPC970_ROM"
#define TARGET_ROM_START        0x00fc0000u
#define TARGET_ROM_SIZE         0x00040000
#define TARGET_CONFIG_REGION    0x02

#define WORKER_FLAGS_IDLE_MASK  0xfc
#define WORKER_FLAGS_TRIGGER    0x03
#define WORKER_ARM_VALUE        1

#define SCMD_VERSION            0x03
#define SCMD_READ_NVRAM         0x0a
#define SCMD_WRITE_NVRAM        0x0b
#define SCMD_OPEN_CONFIG        0x40
#define SCMD_READ_CONFIG        0x41
#define SCMD_WRITE_CONFIG       0x42
#define SCMD_CLOSE_CONFIG       0x43

#define CONFIG_BLOCKS           16
#define CONFIG_BLOCK_SIZE       16
#define NVRAM_WORDS             512
#define NVRAM_BYTES             (NVRAM_WORDS * 2)

#define CHUNK_SIZE              256
#define MAX_CHUNK_COUNT         (TARGET_ROM_SIZE / CHUNK_SIZE)
#define BANK_WORDS              (CHUNK_SIZE / 2)
#define BANK_COUNT              (NVRAM_WORDS / BANK_WORDS)
#define SESSION_SLOT_COUNT      100
#define SESSION_PATH_CAPACITY   64
#define SESSION_NAME_CAPACITY   32
#define LEGACY_SESSION_SLOT     (-1)
#define NO_SESSION_SLOT         (-2)
#define STATUS_INTERVAL_CHUNKS  16
#define START_DELAY_SECONDS     5
#define START_HOLD_TICKS        (START_DELAY_SECONDS * 60)
#define START_HOLD_BAR_WIDTH    24
#define DRIVE_SETTLE_US         3000000

#define USB_DIR                 "mass:/SPC970"
#define LEGACY_DUMP_PATH        USB_DIR "/" TARGET_DUMP_STEM ".BIN"
#define LEGACY_DUMP_MAP_PATH    USB_DIR "/" TARGET_DUMP_STEM ".MAP"
#define LEGACY_STATUS_PATH      USB_DIR "/" TARGET_DUMP_STEM ".TXT"
#define LEGACY_NVRAM_PATH       USB_DIR "/" TARGET_DUMP_STEM ".NVRAM"
#define GENERAL_STATUS_PATH     USB_DIR "/SPC970_STATUS.TXT"
#define RESTORE_STATUS_PATH     USB_DIR "/NVRAM_RESTORE.TXT"
#define LEGACY_VALIDATION_PATH  USB_DIR "/SPC970_VALIDATION.TXT"
#define LEGACY_VALIDATION_NVRAM_PATH USB_DIR "/SPC970_VALIDATION.BIN"
#define NVRAM_PATH_FMT          USB_DIR "/NVRAM%02d.BIN"
#define RESTORE_PATH_FMT        USB_DIR "/NVRAM%02d_RESTORE.BIN"
#define PROBE_PATH_FMT          USB_DIR "/PROBE%02d.BIN"
#define REPORT_PATH_FMT         USB_DIR "/NVRAM%02d.TXT"

#if TARGET_ROM_SIZE % CHUNK_SIZE || MAX_CHUNK_COUNT % 8 || BANK_COUNT != 4 || \
    TARGET_ROM_SIZE != SESSION_ROM_SIZE || CHUNK_SIZE != SESSION_CHUNK_SIZE || \
    MAX_CHUNK_COUNT != SESSION_CHUNK_COUNT || NVRAM_BYTES != SESSION_NVRAM_SIZE
#error Invalid ROM dumper target profile
#endif

static const u8 standard_worker_tail_signature[48] = {
    0x00, 0x00, 0x0b, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x1d, 0x01,
    0x03, 0x08, 0x0e, 0x01, 0x04, 0x07, 0xd6, 0x00,
    0x02, 0x06, 0xc1, 0x00, 0x02, 0x07, 0x00, 0x00,
    0x02, 0x09, 0x13, 0x01, 0x02, 0x09, 0xcc, 0x00
};

static const u8 shifted_worker_tail_signature[48] = {
    0x0b, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x2c, 0x01, 0x1d, 0x01, 0x03, 0x08,
    0x0e, 0x01, 0x04, 0x07, 0xd6, 0x00, 0x02, 0x06,
    0xc1, 0x00, 0x02, 0x07, 0x00, 0x00, 0x02, 0x09,
    0x13, 0x01, 0x02, 0x09, 0xcc, 0x00, 0x01, 0x03
};

struct worker_layout {
    const char *name;
    u8 flags_block;
    u8 flags_byte;
    u8 source_pointer_offset;
    u8 flags_mutable_end_byte;
    u8 control_block;
    u8 source_offset_byte;
    u8 word_count_byte;
    u8 worker_state_byte;
    u8 destination_block;
    u8 destination_low_byte;
    u8 destination_high_byte;
    u8 checksum_adjust_byte;
    u8 scratch_boundary_byte;
    u8 marker_block;
    u8 marker_byte;
    u8 marker_value;
    u32 layout_signature_salt;
    const u8 *tail_signature;
};

static const struct worker_layout known_worker_layouts[] = {
    {
        .name = "standard-fields",
        .flags_block = 11, .flags_byte = 6,
        .source_pointer_offset = 8, .flags_mutable_end_byte = 13,
        .control_block = 12, .source_offset_byte = 12,
        .word_count_byte = 13, .worker_state_byte = 14,
        .destination_block = 13, .destination_low_byte = 0,
        .destination_high_byte = 1, .checksum_adjust_byte = 0xff,
        .scratch_boundary_byte = 4,
        .marker_block = 0xff,
        .layout_signature_salt = 0,
        .tail_signature = standard_worker_tail_signature
    },
    {
        .name = "fields-2-bytes-earlier",
        .flags_block = 11, .flags_byte = 4,
        .source_pointer_offset = 6, .flags_mutable_end_byte = 11,
        .control_block = 12, .source_offset_byte = 10,
        .word_count_byte = 11, .worker_state_byte = 12,
        .destination_block = 12, .destination_low_byte = 14,
        .destination_high_byte = 15, .checksum_adjust_byte = 13,
        .scratch_boundary_byte = 2,
        .marker_block = 11, .marker_byte = 5, .marker_value = 0,
        .layout_signature_salt = 0x32414742u,
        .tail_signature = shifted_worker_tail_signature
    },
    {
        .name = "shifted-marker-01-pointer-at-6",
        .flags_block = 11, .flags_byte = 4,
        .source_pointer_offset = 6, .flags_mutable_end_byte = 11,
        .control_block = 12, .source_offset_byte = 10,
        .word_count_byte = 11, .worker_state_byte = 12,
        .destination_block = 12, .destination_low_byte = 14,
        .destination_high_byte = 15, .checksum_adjust_byte = 13,
        .scratch_boundary_byte = 2,
        .marker_block = 11, .marker_byte = 5, .marker_value = 1,
        .layout_signature_salt = 0x31425948u,
        .tail_signature = shifted_worker_tail_signature
    }
};

static const u8 rom_entry_signature[4] = {0xe6, 0x00, 0xd8, 0xe8};

static const u8 legacy_session_nvram_magic[12] = {
    'S', 'P', 'C', '9', '7', '0', 'N', 'V',
    0x01, 0x00, 0x00, 0x00
};

#define LEGACY_SESSION_NVRAM_HEADER_SIZE 32
#define LEGACY_SESSION_NVRAM_FILE_SIZE \
    (LEGACY_SESSION_NVRAM_HEADER_SIZE + NVRAM_BYTES)

static u8 raw_version[16];
static u8 session_nvram_baseline[NVRAM_BYTES];
static u8 session_nvram_file[SESSION_NVRAM_FILE_SIZE];
static u8 dump_map_file[SESSION_MAP_FILE_SIZE];
static struct session_snapshot session_snapshot = {
    .corrupt_chunk = -1
};
static struct session_profile session_profile;
static char dump_path[SESSION_PATH_CAPACITY];
static char dump_map_path[SESSION_PATH_CAPACITY];
static char session_nvram_path[SESSION_PATH_CAPACITY];
static char session_status_path[SESSION_PATH_CAPACITY];
static char validation_path[SESSION_PATH_CAPACITY];
static char validation_nvram_path[SESSION_PATH_CAPACITY];
static char session_status_name[SESSION_NAME_CAPACITY];
static char validation_status_name[SESSION_NAME_CAPACITY];
static struct session_paths session_paths = {
    dump_path, dump_map_path, session_nvram_path
};
static u8 config_window[CONFIG_BLOCKS][CONFIG_BLOCK_SIZE];
static u8 nvram_image[NVRAM_BYTES];
static u8 restore_nvram[NVRAM_BYTES];
static char restore_report[4096];
static u8 chunk_buffer[CHUNK_SIZE];
static u8 validation_observed[16];
static u8 validation_pre_restore[NVRAM_BYTES];
static u8 dump_progress_bitmap[SESSION_MAP_BITMAP_SIZE];
static u8 session_id[SESSION_ID_SIZE];
static u8 pad_buffers[2][256] __attribute__((aligned(64)));
static char console_name[20] = "unknown console";
static char restore_model[20] = "unknown console";
static int capture_saved;
static const char *capture_failure_reason = "none";
static int dump_status_saved = 1;
static int restore_status_saved = 1;
static int restore_slot = -1;
static int restore_dirty_bank_mask;
static int invalid_restore_marker;
static int controller_opened;
static int active_session_slot = NO_SESSION_SLOT;
static int session_reserved;
static int session_setup_ready;
static const struct worker_layout *active_worker_layout;
static const char *validation_failure_reason = "not-run";
static const char *last_copy_stage = "not-run";
static int last_copy_block = -1;
static int last_copy_transport = -1;
static int last_copy_command_status = -1;
static int last_copy_close_status = -1;
static int last_copy_close_attempts;
static int validation_observed_valid;
static int validation_signature_matches;
static int validation_pre_restore_complete;
static int validation_dirty_words;
static int validation_first_dirty_word = -1;
static int validation_last_dirty_word = -1;
static int validation_restore_succeeded;
static int validation_post_read_succeeded;
static int validation_post_matches;
static int clear_unused_source_bytes;
static enum session_state current_session_state = SESSION_NO_SESSION;

enum copy_result {
    COPY_FAILED_SAFE,
    COPY_SUCCEEDED,
    COPY_WORKER_UNKNOWN
};

#define BANK_VALIDATION_COUNT BANK_COUNT
#define ROM_ENTRY_CANDIDATE_COUNT   2
#define ALTERNATE_ROM_ENTRY_ADDRESS 0x00fd0000u

static const u16 bank_destination_words[BANK_VALIDATION_COUNT] = {
    0, BANK_WORDS, BANK_WORDS * 2, BANK_WORDS * 3
};

struct validation_attempt_result {
    int attempted;
    u32 source_address;
    u16 destination_word;
    enum copy_result copy_status;
    const char *failure_reason;
    const char *copy_stage;
    int copy_block;
    int copy_transport;
    int copy_command_status;
    int close_status;
    int close_attempts;
    int observed_valid;
    u8 observed[16];
    int data_matches;
    int dirty_words;
    int first_dirty_word;
    int last_dirty_word;
    int restore_succeeded;
    int post_restore_matches;
};

static struct validation_attempt_result
    bank_validation_results[BANK_VALIDATION_COUNT];
static struct validation_attempt_result
    entry_validation_results[ROM_ENTRY_CANDIDATE_COUNT];
static u8 selected_rom_entry_bytes[16];
static u32 selected_rom_entry_address;
static int selected_rom_entry_valid;

enum restore_source {
    RESTORE_NONE,
    RESTORE_SESSION,
    RESTORE_NUMBERED,
    RESTORE_INVALID
};

enum startup_action {
    STARTUP_STOP,
    STARTUP_DUMP,
    STARTUP_RESTORE
};

static int is_shifted_marker_01_layout(void)
{
    return active_worker_layout &&
           active_worker_layout->marker_block == 11 &&
           active_worker_layout->marker_byte == 5 &&
           active_worker_layout->marker_value == 1;
}

static const char *copy_result_name(enum copy_result result)
{
    if (result == COPY_SUCCEEDED)
        return "succeeded";
    if (result == COPY_WORKER_UNKNOWN)
        return "worker-unknown";
    return "failed-safe";
}

static void reset_validation_diagnostics(void)
{
    validation_failure_reason = "not-run";
    last_copy_stage = "not-run";
    last_copy_block = -1;
    last_copy_transport = -1;
    last_copy_command_status = -1;
    last_copy_close_status = -1;
    last_copy_close_attempts = 0;
    validation_observed_valid = 0;
    validation_signature_matches = 0;
    validation_pre_restore_complete = 0;
    validation_dirty_words = 0;
    validation_first_dirty_word = -1;
    validation_last_dirty_word = -1;
    validation_restore_succeeded = 0;
    validation_post_read_succeeded = 0;
    validation_post_matches = 0;
    memset(validation_observed, 0, sizeof(validation_observed));
    memcpy(validation_pre_restore, session_nvram_baseline, NVRAM_BYTES);
}

static void save_validation_attempt(struct validation_attempt_result *result,
                                    u32 source_address,
                                    u16 destination_word,
                                    enum copy_result copy_status,
                                    int data_matches)
{
    memset(result, 0, sizeof(*result));
    result->attempted = 1;
    result->source_address = source_address;
    result->destination_word = destination_word;
    result->copy_status = copy_status;
    result->failure_reason = validation_failure_reason;
    result->copy_stage = last_copy_stage;
    result->copy_block = last_copy_block;
    result->copy_transport = last_copy_transport;
    result->copy_command_status = last_copy_command_status;
    result->close_status = last_copy_close_status;
    result->close_attempts = last_copy_close_attempts;
    result->observed_valid = validation_observed_valid;
    memcpy(result->observed, validation_observed,
           sizeof(result->observed));
    result->data_matches = data_matches;
    result->dirty_words = validation_dirty_words;
    result->first_dirty_word = validation_first_dirty_word;
    result->last_dirty_word = validation_last_dirty_word;
    result->restore_succeeded = validation_restore_succeeded;
    result->post_restore_matches = validation_post_matches;
}

static int apply_scmd(u8 command, const void *input, u16 input_size,
                      u8 output[16])
{
    /* SCMD replies use a fixed 16-byte buffer. */
    memset(output, 0, 16);
    return sceCdApplySCmd(command, input, input_size, output);
}

static u32 update_crc32(u32 crc, const u8 *data, int size)
{
    int index;

    while (size-- > 0) {
        crc ^= *data++;
        for (index = 0; index < 8; index++)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return crc;
}

static u32 crc32_bytes(const u8 *data, int size)
{
    return ~update_crc32(0xffffffffu, data, size);
}

static void put_u32le(u8 *output, u32 value)
{
    output[0] = (u8)value;
    output[1] = (u8)(value >> 8);
    output[2] = (u8)(value >> 16);
    output[3] = (u8)(value >> 24);
}

static u32 get_u32le(const u8 *input)
{
    return (u32)input[0] | ((u32)input[1] << 8) |
           ((u32)input[2] << 16) | ((u32)input[3] << 24);
}

static int close_config(void)
{
    u8 output[16];

    if (!apply_scmd(SCMD_CLOSE_CONFIG, NULL, 0, output))
        return -1;
    return output[0];
}

static int read_config_window(void)
{
    const u8 parameters[3] = {
        0x00, TARGET_CONFIG_REGION, CONFIG_BLOCKS
    };
    u8 output[16];
    int block;

    if (!apply_scmd(SCMD_OPEN_CONFIG, parameters, sizeof(parameters), output))
        return 0;
    if (output[0] != 0)
        return 0;

    for (block = 0; block < CONFIG_BLOCKS; block++) {
        if (!apply_scmd(SCMD_READ_CONFIG, NULL, 0,
                        config_window[block])) {
            close_config();
            return 0;
        }
    }
    return close_config() == 0;
}

static int error_block(const u8 block[16])
{
    int index;

    if (block[0] != 0x80)
        return 0;
    for (index = 1; index < 16; index++) {
        if (block[index] != 0)
            return 0;
    }
    return 1;
}

static int config_window_is_extended(void)
{
    int block;
    int index;
    int nonzero = 0;

    /* Blocks after the public seven expose nearby RAM. */
    for (block = 7; block < CONFIG_BLOCKS; block++) {
        if (error_block(config_window[block]))
            return 0;
        for (index = 0; index < CONFIG_BLOCK_SIZE; index++)
            nonzero |= config_window[block][index] != 0;
    }
    return nonzero;
}

static int worker_byte_is_mutable(const struct worker_layout *layout,
                                  int block, int byte)
{
    /* SCMD 42 replaces the last byte with the block checksum. */
    if (byte == CONFIG_BLOCK_SIZE - 1)
        return 1;
    if (block == layout->flags_block &&
        byte >= layout->flags_byte &&
        byte <= layout->flags_mutable_end_byte)
        return 1;
    if (block == layout->control_block &&
        byte >= layout->source_offset_byte &&
        byte <= layout->worker_state_byte)
        return 1;
    return block == layout->destination_block &&
           (byte == layout->destination_low_byte ||
            byte == layout->destination_high_byte ||
            byte == layout->checksum_adjust_byte);
}

static int worker_byte_is_volatile(const struct worker_layout *layout,
                                   int block, int byte)
{
    /* Scratch RAM between the worker and the next stable block. */
    return (block == 13 && byte >= layout->scratch_boundary_byte) ||
           (block == 14 && byte < layout->scratch_boundary_byte);
}

static int worker_layout_matches(const struct worker_layout *layout)
{
    int block;
    int byte;

    if (layout->marker_block != 0xff &&
        config_window[layout->marker_block][layout->marker_byte] !=
            layout->marker_value)
        return 0;

    /* Compare stable bytes while allowing live worker fields to vary. */
    for (block = 8; block < CONFIG_BLOCKS; block++) {
        for (byte = 0; byte < CONFIG_BLOCK_SIZE; byte++) {
            u8 expected = block < 13 ? 0 :
                layout->tail_signature[(block - 13) *
                                       CONFIG_BLOCK_SIZE + byte];
            if (!worker_byte_is_mutable(layout, block, byte) &&
                !worker_byte_is_volatile(layout, block, byte) &&
                config_window[block][byte] != expected)
                return 0;
        }
    }
    return 1;
}

static const struct worker_layout *detect_worker_layout(void)
{
    const struct worker_layout *match = NULL;
    int index;

    for (index = 0;
         index < (int)(sizeof(known_worker_layouts) /
                       sizeof(known_worker_layouts[0]));
         index++) {
        if (worker_layout_matches(&known_worker_layouts[index])) {
            if (match)
                return NULL;
            match = &known_worker_layouts[index];
        }
    }
    return match;
}

static int open_controller(void)
{
    int port;

    if (controller_opened)
        return 1;
    if (padInit(0) != 1)
        return 0;
    for (port = 0; port < 2; port++)
        if (padPortOpen(port, 0, pad_buffers[port]) == 1)
            controller_opened |= 1 << port;
    if (!controller_opened) {
        padEnd();
        return 0;
    }
    return 1;
}

static void close_controller(void)
{
    int port;

    if (!controller_opened)
        return;
    for (port = 0; port < 2; port++)
        if (controller_opened & (1 << port))
            padPortClose(port, 0);
    padEnd();
    controller_opened = 0;
}

static u16 read_pressed_buttons(void)
{
    struct padButtonStatus buttons;
    u16 pressed = 0;
    int port;

    for (port = 0; port < 2; port++) {
        int state;

        if (!(controller_opened & (1 << port)))
            continue;
        state = padGetState(port, 0);
        if ((state == PAD_STATE_STABLE || state == PAD_STATE_FINDCTP1) &&
            padRead(port, 0, &buttons))
            pressed |= 0xffffu ^ buttons.btns;
    }
    return pressed;
}

static int wait_for_hold_confirmation(void)
{
    const u16 confirm_buttons = PAD_L1 | PAD_R1 | PAD_CROSS;
    int buttons_released = 0;
    int confirmed = 0;

    if (!open_controller())
        return 0;
    for (;;) {
        u16 pressed_buttons = read_pressed_buttons();

        if ((pressed_buttons & (confirm_buttons | PAD_CIRCLE)) == 0)
            buttons_released = 1;
        if (buttons_released && (pressed_buttons & PAD_CIRCLE))
            break;
        if (buttons_released &&
            (pressed_buttons & confirm_buttons) == confirm_buttons) {
            confirmed = 1;
            break;
        }
        usleep(16000);
    }
    close_controller();
    return confirmed;
}

static int read_version(void)
{
    const u8 subcommand = 0;

    return apply_scmd(SCMD_VERSION, &subcommand, 1, raw_version);
}

static int read_nvram_word_status(u16 address, u16 *value, u8 *status)
{
    const u8 input[2] = {(u8)(address >> 8), (u8)address};
    u8 output[16];

    if (!apply_scmd(SCMD_READ_NVRAM, input, sizeof(input), output))
        return 0;
    *status = output[0];
    if (*status == 0)
        *value = ((u16)output[1] << 8) | output[2];
    return 1;
}

static int read_nvram_word(u16 address, u16 *value)
{
    u8 status;
    return read_nvram_word_status(address, value, &status) && status == 0;
}

static int read_nvram(void)
{
    int address;

    for (address = 0; address < NVRAM_WORDS; address++) {
        u16 value;
        if (!read_nvram_word((u16)address, &value))
            return 0;
        nvram_image[address * 2] = (u8)(value >> 8);
        nvram_image[address * 2 + 1] = (u8)value;
    }
    return 1;
}

static int read_console_name(const u8 *nvram, char *name, int capacity)
{
    int has_visible_character = 0;
    int limit;
    int index;

    if (!nvram || !name || capacity <= 0)
        return 0;
    limit = capacity - 1;
    if (limit > SESSION_RAW_MODEL_SIZE)
        limit = SESSION_RAW_MODEL_SIZE;
    /* Model text is reversed within each stored 16-bit word. */
    for (index = 0; index < limit; index++) {
        int offset = SESSION_RAW_MODEL_OFFSET + (index ^ 1);
        u8 value = nvram[offset];
        if (value == 0 || value == 0xff)
            break;
        if (value < 0x20 || value > 0x7e)
            return 0;
        name[index] = value;
        has_visible_character |= value != ' ';
    }
    name[index] = 0;
    return index > 0 && has_visible_character;
}

static void identify_console(void)
{
    char detected[sizeof(console_name)];

    snprintf(console_name, sizeof(console_name), "unknown console");
    if (read_console_name(nvram_image, detected, sizeof(detected)))
        snprintf(console_name, sizeof(console_name), "%s", detected);
}

static int find_different_banks(const u8 *first, const u8 *second);

static int load_numbered_restore(void)
{
    char restore_path[48];
    char report_path[48];
    char expected_name[20];
    struct restore_report_fields report;
    int dirty_banks;
    int slot;
    int requests_found = 0;

    restore_slot = -1;
    for (slot = 0; slot < 100; slot++) {
        char path[48];
        snprintf(path, sizeof(path), RESTORE_PATH_FMT, slot);
        if (file_exists(path)) {
            restore_slot = slot;
            requests_found++;
        }
    }
    if (requests_found == 0)
        return 0;
    if (requests_found != 1)
        return -1;

    snprintf(restore_path, sizeof(restore_path),
             RESTORE_PATH_FMT, restore_slot);
    snprintf(report_path, sizeof(report_path), REPORT_PATH_FMT, restore_slot);
    snprintf(expected_name, sizeof(expected_name), "NVRAM%02d.BIN", restore_slot);
    if (!read_exact_file(restore_path, restore_nvram, NVRAM_BYTES) ||
        !read_text_file(report_path, restore_report,
                        sizeof(restore_report)) ||
        !parse_restore_report(restore_report, strlen(restore_report), &report) ||
        strcmp(report.filename, expected_name) != 0 ||
        memcmp(report.version, raw_version, 4) != 0 ||
        report.crc != crc32_bytes(restore_nvram, NVRAM_BYTES))
        return -1;

    dirty_banks = find_different_banks(nvram_image, restore_nvram);
    if (!session_raw_model_matches(nvram_image, restore_nvram))
        return -1;
    if (!read_console_name(restore_nvram, restore_model,
                           sizeof(restore_model)))
        snprintf(restore_model, sizeof(restore_model), "unknown console");
    restore_dirty_bank_mask = dirty_banks;
    return 1;
}

static int nvram_matches_baseline(void)
{
    return memcmp(nvram_image, session_nvram_baseline, NVRAM_BYTES) == 0;
}

static int find_different_banks(const u8 *first, const u8 *second)
{
    int dirty_banks = 0;
    int offset;

    for (offset = 0; offset < NVRAM_BYTES; offset++)
        if (first[offset] != second[offset])
            dirty_banks |= 1 << (offset / CHUNK_SIZE);
    return dirty_banks;
}

static int wait_for_nvram_word(u16 address, u16 expected)
{
    int attempt;

    for (attempt = 0; attempt < 1000; attempt++) {
        u16 value = 0;
        u8 status = 0xff;
        if (read_nvram_word_status(address, &value, &status)) {
            if (status == 0)
                return value == expected;
            if (status != 1)
                return 0;
        }
        usleep(10000);
    }
    return 0;
}

static int write_nvram_word(u16 address, u16 value)
{
    const u8 input[4] = {
        (u8)(address >> 8), (u8)address,
        (u8)(value >> 8), (u8)value
    };
    int attempt;

    for (attempt = 0; attempt < 1000; attempt++) {
        u8 output[16];
        if (!apply_scmd(SCMD_WRITE_NVRAM, input, sizeof(input), output))
            return wait_for_nvram_word(address, value);
        if (output[0] == 0)
            return wait_for_nvram_word(address, value);
        if (output[0] != 1)
            return 0;
        usleep(10000);
    }
    return 0;
}

static int restore_validation_nvram(void)
{
    int index;

    memcpy(validation_pre_restore, session_nvram_baseline, NVRAM_BYTES);

    /* Record each changed word, then restore it immediately. */
    for (index = 0; index < NVRAM_WORDS; index++) {
        u16 expected = ((u16)session_nvram_baseline[index * 2] << 8) |
                       session_nvram_baseline[index * 2 + 1];
        u16 current;

        if (!read_nvram_word((u16)index, &current))
            return 0;
        if (current != expected) {
            validation_pre_restore[index * 2] = (u8)(current >> 8);
            validation_pre_restore[index * 2 + 1] = (u8)current;
            validation_dirty_words++;
            if (validation_first_dirty_word < 0)
                validation_first_dirty_word = index;
            validation_last_dirty_word = index;
            if (!write_nvram_word((u16)index, expected))
                return 0;
        }
    }
    validation_pre_restore_complete = 1;

    for (index = 0; index < NVRAM_WORDS; index++) {
        u16 expected = ((u16)session_nvram_baseline[index * 2] << 8) |
                       session_nvram_baseline[index * 2 + 1];
        u16 current;

        if (!read_nvram_word((u16)index, &current) || current != expected)
            return 0;
    }
    return 1;
}

static void show_restore_progress(const char *phase, int complete, int total)
{
    scr_setXY(4, 10);
    scr_printf("%s: %d / %d       \n", phase, complete, total);
}

static int restore_nvram_words_with_progress(const u8 *backup,
                                             int first_word,
                                             int word_count)
{
    int index;

    for (index = 0; index < word_count; index++) {
        u16 address = first_word + index;
        u16 expected = ((u16)backup[address * 2] << 8) |
                       backup[address * 2 + 1];
        u16 current;
        if ((index & 7) == 0)
            show_restore_progress("RESTORE", index, word_count);
        if (!read_nvram_word(address, &current))
            return 0;
        if (current != expected) {
            show_restore_progress("WRITING", index + 1, word_count);
            if (!write_nvram_word(address, expected))
                return 0;
        }
    }
    show_restore_progress("VERIFY", 0, word_count);
    for (index = 0; index < word_count; index++) {
        u16 address = first_word + index;
        u16 expected = ((u16)backup[address * 2] << 8) |
                       backup[address * 2 + 1];
        u16 current;
        if ((index & 7) == 0)
            show_restore_progress("VERIFY", index, word_count);
        if (!read_nvram_word(address, &current) || current != expected)
            return 0;
        nvram_image[address * 2] = (u8)(current >> 8);
        nvram_image[address * 2 + 1] = (u8)current;
    }
    show_restore_progress("VERIFY", word_count, word_count);
    return 1;
}

static int write_capture_report(int slot, u32 nvram_crc, u32 probe_crc)
{
    char path[48];
    char report[768];
    int length;

    snprintf(path, sizeof(path), REPORT_PATH_FMT, slot);
    length = snprintf(report, sizeof(report),
        PROJECT_NAME " CAPTURE\n"
        "built=%s %s\n"
        "console_model=%s\n"
        "raw_scmd_03_00=%02X %02X %02X %02X\n"
        "worker_layout=%s\n"
        "nvram_file=NVRAM%02d.BIN\n"
        "nvram_crc32=%08lX\n"
        "probe_file=PROBE%02d.BIN\n"
        "probe_crc32=%08lX\n",
        BUILD_DATE, BUILD_TIME, console_name,
        raw_version[0], raw_version[1], raw_version[2], raw_version[3],
        active_worker_layout ? active_worker_layout->name : "unknown",
        slot, (unsigned long)nvram_crc,
        slot, (unsigned long)probe_crc);
    if (length <= 0 || length >= (int)sizeof(report))
        return 0;
    return write_new_verified_file(path, report, length);
}

static int save_capture(void)
{
    char nvram_path[48];
    char probe_path[48];
    int slot;
    int saved;

    capture_failure_reason = "capture-save-failed";
    slot = find_capture_slot(USB_DIR);
    if (slot == CAPTURE_SLOTS_FULL) {
        capture_failure_reason = "capture-slots-full";
        return 0;
    }
    if (slot < 0)
        return 0;
    snprintf(nvram_path, sizeof(nvram_path), NVRAM_PATH_FMT, slot);
    snprintf(probe_path, sizeof(probe_path), PROBE_PATH_FMT, slot);
    if (!write_new_verified_file(nvram_path, nvram_image, NVRAM_BYTES))
        return 0;
    if (!write_new_verified_file(probe_path, config_window,
                                 sizeof(config_window)))
        return 0;
    saved = write_capture_report(
        slot, crc32_bytes(nvram_image, NVRAM_BYTES),
        crc32_bytes((const u8 *)config_window, sizeof(config_window)));
    if (saved)
        capture_failure_reason = "none";
    return saved;
}

static void set_session_paths(int slot)
{
    active_session_slot = slot;
    if (slot == LEGACY_SESSION_SLOT) {
        snprintf(dump_path, sizeof(dump_path), "%s", LEGACY_DUMP_PATH);
        snprintf(dump_map_path, sizeof(dump_map_path), "%s",
                 LEGACY_DUMP_MAP_PATH);
        snprintf(session_nvram_path, sizeof(session_nvram_path), "%s",
                 LEGACY_NVRAM_PATH);
        snprintf(session_status_path, sizeof(session_status_path), "%s",
                 LEGACY_STATUS_PATH);
        snprintf(validation_path, sizeof(validation_path), "%s",
                 LEGACY_VALIDATION_PATH);
        snprintf(validation_nvram_path, sizeof(validation_nvram_path), "%s",
                 LEGACY_VALIDATION_NVRAM_PATH);
        snprintf(session_status_name, sizeof(session_status_name),
                 TARGET_DUMP_STEM ".TXT");
        snprintf(validation_status_name, sizeof(validation_status_name),
                 "SPC970_VALIDATION.TXT");
        return;
    }

    snprintf(dump_path, sizeof(dump_path),
             USB_DIR "/" TARGET_DUMP_STEM "_%03d.BIN", slot);
    snprintf(dump_map_path, sizeof(dump_map_path),
             USB_DIR "/" TARGET_DUMP_STEM "_%03d.MAP", slot);
    snprintf(session_nvram_path, sizeof(session_nvram_path),
             USB_DIR "/" TARGET_DUMP_STEM "_%03d.NVRAM", slot);
    snprintf(session_status_path, sizeof(session_status_path),
             USB_DIR "/" TARGET_DUMP_STEM "_%03d.TXT", slot);
    snprintf(validation_path, sizeof(validation_path),
             USB_DIR "/SPC970_VALIDATION_%03d.TXT", slot);
    snprintf(validation_nvram_path, sizeof(validation_nvram_path),
             USB_DIR "/SPC970_VALIDATION_%03d.BIN", slot);
    snprintf(session_status_name, sizeof(session_status_name),
             TARGET_DUMP_STEM "_%03d.TXT", slot);
    snprintf(validation_status_name, sizeof(validation_status_name),
             "SPC970_VALIDATION_%03d.TXT", slot);
}

static int session_slot_occupied(void)
{
    return file_exists(session_paths.rom) || file_exists(session_paths.map) ||
           file_exists(session_paths.nvram) ||
           file_exists(session_status_path) || file_exists(validation_path) ||
           file_exists(validation_nvram_path);
}

static const char *status_output_path(void)
{
    return session_reserved ? session_status_path : GENERAL_STATUS_PATH;
}

static void write_status(const char *state, int current_chunk,
                         int completed_chunks, u32 crc, int crc_valid)
{
    char report[640];
    char slot_text[12];
    int length;

    dump_status_saved = 0;

    if (active_session_slot == LEGACY_SESSION_SLOT)
        snprintf(slot_text, sizeof(slot_text), "legacy");
    else if (active_session_slot >= 0)
        snprintf(slot_text, sizeof(slot_text), "%03d", active_session_slot);
    else
        snprintf(slot_text, sizeof(slot_text), "none");

    length = snprintf(report, sizeof(report),
        PROJECT_NAME " ROM DUMP\n"
        "built=%s %s\n"
        "console_model=%s\n"
        "raw_scmd_03_00=%02X %02X %02X %02X\n"
        "worker_layout=%s\n"
        "session_slot=%s\n"
        "state=%s\n"
        "session_state=%s\n"
        "progress_chunks=%d/%d\n",
        BUILD_DATE, BUILD_TIME, console_name,
        raw_version[0], raw_version[1], raw_version[2], raw_version[3],
        active_worker_layout ? active_worker_layout->name : "unknown",
        slot_text,
        state,
        session_state_name(current_session_state),
        completed_chunks, MAX_CHUNK_COUNT);
    if (length <= 0 || length >= (int)sizeof(report))
        return;
    if (current_chunk >= 0) {
        int written = snprintf(report + length, sizeof(report) - length,
                               "current_chunk=%d/%d\n",
                               current_chunk + 1, MAX_CHUNK_COUNT);
        if (written <= 0 || written >= (int)sizeof(report) - length)
            return;
        length += written;
    }
    if (current_session_state == SESSION_CORRUPT_ROM_CHUNKS) {
        int written = snprintf(report + length, sizeof(report) - length,
                               "corrupt_chunk=%d\n",
                               session_snapshot.corrupt_chunk);
        if (written <= 0 || written >= (int)sizeof(report) - length)
            return;
        length += written;
    }
    if (crc_valid) {
        int written = snprintf(report + length, sizeof(report) - length,
                               "crc32=%08lX\n", (unsigned long)crc);
        if (written <= 0 || written >= (int)sizeof(report) - length)
            return;
        length += written;
    }
    dump_status_saved = replace_verified_file(
        status_output_path(), report, length);
}

static void write_restore_status(const char *state,
                                 enum restore_source source,
                                 int post_capture_saved)
{
    char report[512];
    char source_file[24];
    int length;

    restore_status_saved = 0;

    if (source == RESTORE_SESSION) {
        if (active_session_slot == LEGACY_SESSION_SLOT)
            snprintf(source_file, sizeof(source_file), "%s.NVRAM",
                     TARGET_DUMP_STEM);
        else
            snprintf(source_file, sizeof(source_file), "%s_%03d.NVRAM",
                     TARGET_DUMP_STEM, active_session_slot);
    }
    else if (source == RESTORE_NUMBERED)
        snprintf(source_file, sizeof(source_file), "NVRAM%02d.BIN",
                 restore_slot);
    else
        snprintf(source_file, sizeof(source_file), "none");
    length = snprintf(report, sizeof(report),
        PROJECT_NAME " NVRAM RESTORE\n"
        "built=%s %s\n"
        "state=%s\n"
        "source=%s\n"
        "backup_file=%s\n"
        "backup_model=%s\n"
        "raw_scmd_03_00=%02X %02X %02X %02X\n"
        "backup_crc32=%08lX\n"
        "nvram_changed=%s\n"
        "pre_restore_capture=%s\n"
        "post_restore_capture=%s\n",
        BUILD_DATE, BUILD_TIME, state,
        source == RESTORE_SESSION ? "session-baseline" :
        source == RESTORE_NUMBERED ? "numbered-backup" : "none",
        source_file, restore_model,
        raw_version[0], raw_version[1], raw_version[2], raw_version[3],
        (unsigned long)crc32_bytes(restore_nvram, NVRAM_BYTES),
        restore_dirty_bank_mask ? "yes" : "no",
        capture_saved ? "verified" : "failed",
        post_capture_saved ? "verified" : "not-saved");
    if (length <= 0 || length >= (int)sizeof(report))
        return;
    if (strcmp(capture_failure_reason, "none") != 0) {
        int written = snprintf(report + length, sizeof(report) - length,
                               "capture_error=%s\n",
                               capture_failure_reason);
        if (written <= 0 || written >= (int)sizeof(report) - length)
            return;
        length += written;
    }
    restore_status_saved = replace_verified_file(
        RESTORE_STATUS_PATH, report, length);
}

static int append_attempt_report(char *report, int capacity, int length,
                                 const char *kind, int index,
                                 const struct validation_attempt_result *result)
{
    char observed[64];
    char changes[48];
    int written;

    if (!result->attempted) {
        written = snprintf(report + length, capacity - length,
                           "attempt=%s-%d\nresult=not-run\n",
                           kind, index);
        if (written <= 0 || written >= capacity - length)
            return -1;
        return length + written;
    }
    if (result->observed_valid)
        snprintf(observed, sizeof(observed),
            "%02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X",
            result->observed[0], result->observed[1],
            result->observed[2], result->observed[3],
            result->observed[4], result->observed[5],
            result->observed[6], result->observed[7],
            result->observed[8], result->observed[9],
            result->observed[10], result->observed[11],
            result->observed[12], result->observed[13],
            result->observed[14], result->observed[15]);
    else
        snprintf(observed, sizeof(observed), "unavailable");
    if (result->dirty_words > 0)
        snprintf(changes, sizeof(changes), "%d words (%d-%d)",
                 result->dirty_words, result->first_dirty_word,
                 result->last_dirty_word);
    else
        snprintf(changes, sizeof(changes), "none");

    written = snprintf(report + length, capacity - length,
        "attempt=%s-%d\n"
        "result=%s\n"
        "source_address=%08lX\n"
        "destination_word=%u\n"
        "observed_16=%s\n"
        "data_matches=%s\n"
        "nvram_changes=%s\n"
        "restore_succeeded=%s\n"
        "post_restore_matches=%s\n",
        kind, index, copy_result_name(result->copy_status),
        (unsigned long)result->source_address, result->destination_word,
        observed, result->data_matches ? "yes" : "no", changes,
        result->restore_succeeded ? "yes" : "no",
        result->post_restore_matches ? "yes" : "no");

    if (written <= 0 || written >= capacity - length)
        return -1;
    length += written;
    if (strcmp(result->failure_reason, "passed") != 0) {
        written = snprintf(report + length, capacity - length,
            "failure_reason=%s\n"
            "copy_stage=%s\n"
            "copy_status=block:%d transport:%d command:%d close:%d attempts:%d\n",
            result->failure_reason, result->copy_stage,
            result->copy_block, result->copy_transport,
            result->copy_command_status, result->close_status,
            result->close_attempts);
        if (written <= 0 || written >= capacity - length)
            return -1;
        length += written;
    }
    return length;
}

static int write_validation_report(enum copy_result copy_status)
{
    struct validation_attempt_result attempt;
    char report[2048];
    char pre_restore_crc[16];
    char post_restore_crc[16];
    int pre_restore_file_saved = 0;
    int length;

    if (validation_pre_restore_complete)
        snprintf(pre_restore_crc, sizeof(pre_restore_crc), "%08lX",
                 (unsigned long)crc32_bytes(validation_pre_restore,
                                            NVRAM_BYTES));
    else
        snprintf(pre_restore_crc, sizeof(pre_restore_crc), "unavailable");
    if (validation_post_read_succeeded)
        snprintf(post_restore_crc, sizeof(post_restore_crc), "%08lX",
                 (unsigned long)crc32_bytes(nvram_image, NVRAM_BYTES));
    else
        snprintf(post_restore_crc, sizeof(post_restore_crc), "unavailable");
    if (validation_pre_restore_complete)
        pre_restore_file_saved = write_verified_file(
            validation_nvram_path, validation_pre_restore, NVRAM_BYTES);
    save_validation_attempt(&attempt, TARGET_ROM_START, 0,
                            copy_status,
                            validation_signature_matches);
    length = snprintf(report, sizeof(report),
        PROJECT_NAME " WORKER VALIDATION\n"
        "built=%s %s\n"
        "console_model=%s\n"
        "raw_scmd_03_00=%02X %02X %02X %02X\n"
        "worker_layout=%s\n"
        "result=%s\n"
        "expected_entry_signature=E6 00 D8 E8\n"
        "baseline_crc32=%08lX\n"
        "pre_restore_crc32=%s\n"
        "post_restore_crc32=%s\n"
        "pre_restore_file=%s\n",
        BUILD_DATE, BUILD_TIME, console_name,
        raw_version[0], raw_version[1], raw_version[2], raw_version[3],
        active_worker_layout ? active_worker_layout->name : "unknown",
        copy_status == COPY_SUCCEEDED && validation_signature_matches &&
            validation_restore_succeeded && validation_post_matches ?
            "passed" : "failed",
        (unsigned long)crc32_bytes(session_nvram_baseline, NVRAM_BYTES),
        pre_restore_crc, post_restore_crc,
        pre_restore_file_saved ? "verified" : "not-saved");
    if (length <= 0 || length >= (int)sizeof(report))
        return 0;
    length = append_attempt_report(report, sizeof(report), length,
                                   "worker", 0, &attempt);
    return length > 0 && replace_verified_file(
        validation_path, report, length);
}

static int write_bank_validation_report(void)
{
    char report[4096];
    char selected_address[16];
    int completed = 0;
    int length;
    int index;

    for (index = 0; index < BANK_VALIDATION_COUNT; index++) {
        const struct validation_attempt_result *result =
            &bank_validation_results[index];
        if (result->attempted && result->copy_status == COPY_SUCCEEDED &&
            result->data_matches && result->restore_succeeded &&
            result->post_restore_matches)
            completed++;
    }
    if (selected_rom_entry_valid)
        snprintf(selected_address, sizeof(selected_address), "%08lX",
                 (unsigned long)selected_rom_entry_address);
    else
        snprintf(selected_address, sizeof(selected_address), "unavailable");

    length = snprintf(report, sizeof(report),
        PROJECT_NAME " FOUR-BANK VALIDATION\n"
        "built=%s %s\n"
        "console_model=%s\n"
        "raw_scmd_03_00=%02X %02X %02X %02X\n"
        "worker_layout=%s\n"
        "result=%s\n"
        "selected_entry_address=%s\n"
        "banks_verified=%d/%d\n"
        "baseline_crc32=%08lX\n",
        BUILD_DATE, BUILD_TIME, console_name,
        raw_version[0], raw_version[1], raw_version[2], raw_version[3],
        active_worker_layout ? active_worker_layout->name : "unknown",
        selected_rom_entry_valid && completed == BANK_VALIDATION_COUNT ?
            "passed" : "failed",
        selected_address,
        completed, BANK_VALIDATION_COUNT,
        (unsigned long)crc32_bytes(session_nvram_baseline, NVRAM_BYTES));
    if (length <= 0 || length >= (int)sizeof(report))
        return 0;

    for (index = 0;
         index < ROM_ENTRY_CANDIDATE_COUNT && length > 0;
         index++)
        length = append_attempt_report(
            report, sizeof(report), length, "entry", index,
            &entry_validation_results[index]);
    /* The selected entry attempt already verifies destination bank zero. */
    for (index = 1; index < BANK_VALIDATION_COUNT && length > 0; index++)
        length = append_attempt_report(
            report, sizeof(report), length, "bank", index,
            &bank_validation_results[index]);
    return length > 0 && replace_verified_file(
        validation_path, report, length);
}

static u32 worker_layout_signature(const struct worker_layout *layout)
{
    return crc32_bytes(layout->tail_signature,
                       sizeof(standard_worker_tail_signature)) ^
           layout->layout_signature_salt;
}

static void initialize_session_profile(void)
{
    session_profile.rom_start = TARGET_ROM_START;
    session_profile.layout_signature = active_worker_layout ?
        worker_layout_signature(active_worker_layout) : 0;
    memcpy(session_profile.raw_version, raw_version,
           sizeof(session_profile.raw_version));
}

static void generate_session_id(void)
{
    u64 time = GetTimerSystemTime();
    u32 baseline_crc = crc32_bytes(session_nvram_baseline, NVRAM_BYTES);
    u32 probe_crc = crc32_bytes((const u8 *)config_window,
                                sizeof(config_window));

    put_u32le(session_id, baseline_crc ^ (u32)time);
    put_u32le(session_id + 4, probe_crc ^ (u32)(time >> 32));
    put_u32le(session_id + 8,
              session_profile.layout_signature ^ (u32)(time >> 17));
    put_u32le(session_id + 12,
              crc32_bytes(raw_version, 16) ^ (u32)(time >> 7));
}

static int prepare_session_baseline(void)
{
    int created = 0;

    if (file_exists(session_paths.rom) || file_exists(session_paths.map) ||
        file_exists(session_paths.nvram) || !active_worker_layout)
        return 0;
    memcpy(session_nvram_baseline, nvram_image, NVRAM_BYTES);
    generate_session_id();
    session_build_nvram_file(session_nvram_file, &session_profile,
                             session_id, session_nvram_baseline);
    if (!write_new_verified_file_tracked(
            session_paths.nvram, session_nvram_file,
            sizeof(session_nvram_file), &created)) {
        if (created)
            unlink(session_paths.nvram);
        return 0;
    }
    session_reserved = 1;
    return 1;
}

static int create_session_files(void)
{
    int dump_created = 0;
    int map_created = 0;

    if (file_exists(session_paths.rom) || file_exists(session_paths.map) ||
        !file_has_size(session_paths.nvram, SESSION_NVRAM_FILE_SIZE))
        return 0;
    if (!write_new_zero_file_tracked(session_paths.rom, TARGET_ROM_SIZE,
                                     &dump_created)) {
        if (dump_created)
            unlink(session_paths.rom);
        return 0;
    }
    session_build_map_file(dump_map_file, &session_profile, session_id,
                           session_crc32(session_nvram_baseline, NVRAM_BYTES));
    if (!write_new_verified_file_tracked(
            session_paths.map, dump_map_file, sizeof(dump_map_file),
            &map_created)) {
        if (map_created)
            unlink(session_paths.map);
        if (dump_created)
            unlink(session_paths.rom);
        return 0;
    }
    map_created = 1;
    current_session_state = session_inspect(&session_paths, &session_profile,
                                            &session_snapshot);
    if (current_session_state != SESSION_VALID_SESSION) {
        if (map_created)
            unlink(session_paths.map);
        if (dump_created)
            unlink(session_paths.rom);
        return 0;
    }
    memcpy(dump_progress_bitmap, session_snapshot.bitmap,
           sizeof(dump_progress_bitmap));
    return 1;
}

static int load_legacy_session_baseline(int allow_legacy_layout)
{
    u32 saved_layout_signature;
    u32 legacy_layout_signature;

    if (!allow_legacy_layout ||
        !file_has_size(session_paths.nvram,
                       LEGACY_SESSION_NVRAM_FILE_SIZE) ||
        !read_exact_file(session_paths.nvram, session_nvram_file,
                         LEGACY_SESSION_NVRAM_FILE_SIZE) ||
        memcmp(session_nvram_file, legacy_session_nvram_magic,
               sizeof(legacy_session_nvram_magic)) != 0 ||
        memcmp(session_nvram_file + 12, raw_version, 4) != 0 ||
        get_u32le(session_nvram_file + 20) != TARGET_ROM_START ||
        get_u32le(session_nvram_file + 24) != TARGET_ROM_SIZE ||
        get_u32le(session_nvram_file + 16) !=
            crc32_bytes(session_nvram_file +
                        LEGACY_SESSION_NVRAM_HEADER_SIZE, NVRAM_BYTES))
        return 0;
    saved_layout_signature = get_u32le(session_nvram_file + 28);
    legacy_layout_signature = crc32_bytes(
        active_worker_layout->tail_signature,
        sizeof(standard_worker_tail_signature));
    if (saved_layout_signature != session_profile.layout_signature &&
        !(active_worker_layout->layout_signature_salt != 0 &&
          saved_layout_signature == legacy_layout_signature))
        return 0;
    memcpy(session_nvram_baseline,
           session_nvram_file + LEGACY_SESSION_NVRAM_HEADER_SIZE,
           NVRAM_BYTES);
    memset(session_id, 0, sizeof(session_id));
    return 1;
}

static int load_session_baseline(int allow_legacy_layout)
{
    if (session_load_current_baseline(session_paths.nvram, &session_profile,
                                      &session_snapshot)) {
        memcpy(session_nvram_baseline, session_snapshot.baseline,
               NVRAM_BYTES);
        memcpy(session_id, session_snapshot.id, sizeof(session_id));
        return 1;
    }
    return load_legacy_session_baseline(allow_legacy_layout);
}

static enum session_state refresh_session_state(void)
{
    current_session_state = session_inspect(&session_paths, &session_profile,
                                            &session_snapshot);
    if (current_session_state == SESSION_VALID_SESSION) {
        memcpy(session_nvram_baseline, session_snapshot.baseline,
               NVRAM_BYTES);
        memcpy(session_id, session_snapshot.id, sizeof(session_id));
        memcpy(dump_progress_bitmap, session_snapshot.bitmap,
               sizeof(dump_progress_bitmap));
    }
    return current_session_state;
}

static int load_session(int *completed_chunks)
{
    if (refresh_session_state() != SESSION_VALID_SESSION)
        return 0;
    *completed_chunks = session_snapshot.completed_chunks;
    return 1;
}

static int read_saved_dump_chunk(int chunk, u8 data[CHUNK_SIZE])
{
    if (chunk < 0 || chunk >= MAX_CHUNK_COUNT)
        return 0;
    return read_file_range(session_paths.rom, chunk * CHUNK_SIZE,
                           data, CHUNK_SIZE);
}

static int last_completed_chunk_for_bank(int completed_chunks, int bank)
{
    int chunk;

    for (chunk = completed_chunks - 1; chunk >= 0; chunk--)
        if (chunk % BANK_COUNT == bank)
            return chunk;
    return -1;
}

static int nvram_matches_saved_dump_state(int completed_chunks)
{
    u8 saved_banks[NVRAM_BYTES];
    unsigned int saved_bank_mask = 0;
    int active_bank = completed_chunks < MAX_CHUNK_COUNT ?
                      completed_chunks % BANK_COUNT : -1;
    int bank;

    memset(saved_banks, 0, sizeof(saved_banks));
    for (bank = 0; bank < BANK_COUNT; bank++) {
        int chunk;

        if (bank == active_bank)
            continue;
        chunk = last_completed_chunk_for_bank(completed_chunks, bank);
        if (chunk >= 0) {
            if (!read_saved_dump_chunk(
                    chunk, saved_banks + bank * CHUNK_SIZE))
                return 0;
            saved_bank_mask |= 1u << bank;
        }
    }
    return session_recovery_words_match(
        nvram_image, session_nvram_baseline, saved_banks,
        saved_bank_mask, active_bank);
}

static int session_recovery_is_safe(int completed_chunks)
{
    if (current_session_state == SESSION_VALID_SESSION)
        return nvram_matches_saved_dump_state(completed_chunks);
    return session_matching_baseline_banks(
               nvram_image, session_nvram_baseline) >= BANK_COUNT - 1;
}

static void remember_session_snapshot(const struct session_snapshot *snapshot)
{
    session_snapshot = *snapshot;
    memcpy(session_nvram_baseline, snapshot->baseline, NVRAM_BYTES);
    memcpy(session_id, snapshot->id, sizeof(session_id));
    memcpy(dump_progress_bitmap, snapshot->bitmap,
           sizeof(dump_progress_bitmap));
}

static enum session_state select_session_slot(void)
{
    enum session_state attention_state = SESSION_NO_SESSION;
    int attention_slot = NO_SESSION_SLOT;
    int candidate_slot = NO_SESSION_SLOT;
    int candidate_count = 0;
    int free_slot = NO_SESSION_SLOT;
    int scan;

    session_setup_ready = 0;
    for (scan = LEGACY_SESSION_SLOT; scan < SESSION_SLOT_COUNT; scan++) {
        struct session_snapshot snapshot;
        enum session_state state;
        int occupied;

        set_session_paths(scan);
        occupied = session_slot_occupied();
        if (scan >= 0 && !occupied && free_slot == NO_SESSION_SLOT)
            free_slot = scan;
        state = session_inspect(&session_paths, &session_profile, &snapshot);
        if (state == SESSION_NO_SESSION)
            continue;
        if (state == SESSION_DIFFERENT_CONSOLE)
            continue;
        if (state == SESSION_VALID_SESSION) {
            current_session_state = state;
            remember_session_snapshot(&snapshot);
            if (session_recovery_is_safe(snapshot.completed_chunks)) {
                candidate_slot = scan;
                candidate_count++;
            } else if (snapshot.completed_chunks < MAX_CHUNK_COUNT &&
                       attention_slot == NO_SESSION_SLOT) {
                attention_slot = scan;
                attention_state = SESSION_DIFFERENT_CONSOLE;
            }
            continue;
        }
        if (state == SESSION_INCOMPLETE_FILES) {
            enum session_baseline_state baseline_state =
                session_inspect_baseline(session_paths.nvram,
                                         &session_profile, &snapshot);

            if (baseline_state == SESSION_BASELINE_DIFFERENT_CONSOLE)
                continue;
            if (baseline_state == SESSION_BASELINE_VALID) {
                current_session_state = state;
                remember_session_snapshot(&snapshot);
                if (session_recovery_is_safe(0)) {
                    candidate_slot = scan;
                    candidate_count++;
                } else if (attention_slot == NO_SESSION_SLOT) {
                    attention_slot = scan;
                    attention_state = SESSION_INCOMPLETE_FILES;
                }
                continue;
            }
            if (attention_slot == NO_SESSION_SLOT) {
                attention_slot = scan;
                attention_state =
                    baseline_state == SESSION_BASELINE_INCOMPATIBLE ?
                    SESSION_INCOMPATIBLE_FORMAT :
                    baseline_state == SESSION_BASELINE_CORRUPT ?
                    SESSION_CORRUPT_METADATA : SESSION_INCOMPLETE_FILES;
            }
            continue;
        }
        if (state == SESSION_INCOMPATIBLE_FORMAT &&
            scan == LEGACY_SESSION_SLOT &&
            load_legacy_session_baseline(1)) {
            current_session_state = state;
            if (session_recovery_is_safe(0)) {
                candidate_slot = scan;
                candidate_count++;
                continue;
            }
        }
        if (attention_slot == NO_SESSION_SLOT) {
            attention_slot = scan;
            attention_state = state;
        }
    }

    if (candidate_count > 1) {
        active_session_slot = NO_SESSION_SLOT;
        session_reserved = 0;
        current_session_state = SESSION_AMBIGUOUS_SESSIONS;
        return current_session_state;
    }
    if (candidate_count == 1) {
        struct session_snapshot snapshot;
        enum session_state state;

        set_session_paths(candidate_slot);
        session_reserved = 1;
        state = session_inspect(&session_paths, &session_profile, &snapshot);
        current_session_state = state;
        if (state == SESSION_VALID_SESSION) {
            remember_session_snapshot(&snapshot);
        } else if (state == SESSION_INCOMPLETE_FILES &&
                   session_inspect_baseline(
                       session_paths.nvram, &session_profile, &snapshot) ==
                   SESSION_BASELINE_VALID) {
            remember_session_snapshot(&snapshot);
            session_setup_ready = !file_exists(session_paths.rom) &&
                                  !file_exists(session_paths.map) &&
                                  memcmp(nvram_image,
                                         session_nvram_baseline,
                                         NVRAM_BYTES) == 0;
        } else if (state == SESSION_INCOMPATIBLE_FORMAT) {
            load_legacy_session_baseline(1);
        }
        return current_session_state;
    }
    if (attention_slot != NO_SESSION_SLOT) {
        set_session_paths(attention_slot);
        session_reserved = 0;
        current_session_state = attention_state;
        return current_session_state;
    }
    if (free_slot != NO_SESSION_SLOT) {
        set_session_paths(free_slot);
        session_reserved = 0;
        memset(&session_snapshot, 0, sizeof(session_snapshot));
        session_snapshot.corrupt_chunk = -1;
        current_session_state = SESSION_NO_SESSION;
        return current_session_state;
    }

    active_session_slot = NO_SESSION_SLOT;
    session_reserved = 0;
    current_session_state = SESSION_SLOTS_FULL;
    return current_session_state;
}

static enum restore_source detect_restore_source(void)
{
    int completed_chunks = 0;
    int session_available = 0;
    int numbered_result = load_numbered_restore();

    invalid_restore_marker = numbered_result < 0;
    if (numbered_result > 0)
        return RESTORE_NUMBERED;
    if (active_session_slot == NO_SESSION_SLOT)
        return numbered_result < 0 ? RESTORE_INVALID : RESTORE_NONE;

    if (load_session_baseline(1)) {
        if (current_session_state == SESSION_VALID_SESSION)
            completed_chunks = session_snapshot.completed_chunks;
        session_available = session_recovery_is_safe(completed_chunks);
        if (current_session_state == SESSION_VALID_SESSION &&
            !session_available)
            current_session_state = SESSION_DIFFERENT_CONSOLE;
    }
    if (session_available) {
        int dirty_banks = find_different_banks(
            nvram_image, session_nvram_baseline);
        if (!dirty_banks)
            return invalid_restore_marker ? RESTORE_INVALID : RESTORE_NONE;
        memcpy(restore_nvram, session_nvram_baseline, NVRAM_BYTES);
        if (!read_console_name(restore_nvram, restore_model,
                               sizeof(restore_model)))
            snprintf(restore_model, sizeof(restore_model),
                     "unknown console");
        restore_slot = -1;
        restore_dirty_bank_mask = dirty_banks;
        return RESTORE_SESSION;
    }
    return numbered_result < 0 ? RESTORE_INVALID : RESTORE_NONE;
}

static int mark_chunk_complete(int chunk)
{
    if (chunk < 0 || chunk >= MAX_CHUNK_COUNT)
        return 0;
    int map_index = chunk >> 3;
    int file_offset = SESSION_MAP_BITMAP_OFFSET + map_index;
    u8 value = dump_progress_bitmap[map_index] | (1u << (chunk & 7));
    u8 check;

    /* One bit represents one verified 256-byte chunk. */
    if (!write_file_range(session_paths.map, file_offset, &value, 1) ||
        !read_file_range(session_paths.map, file_offset, &check, 1) ||
        check != value)
        return 0;
    dump_progress_bitmap[map_index] = value;
    return 1;
}

static int write_chunk_crc(int chunk, const u8 data[CHUNK_SIZE])
{
    u8 encoded[4];
    u8 check[4];
    int offset;

    if (chunk < 0 || chunk >= MAX_CHUNK_COUNT)
        return 0;
    offset = SESSION_MAP_CRC_OFFSET + chunk * 4;
    put_u32le(encoded, session_crc32(data, CHUNK_SIZE));
    if (!write_file_range(session_paths.map, offset, encoded,
                          sizeof(encoded)) ||
        !read_file_range(session_paths.map, offset, check, sizeof(check)) ||
        memcmp(encoded, check, sizeof(encoded)) != 0)
        return 0;
    memcpy(session_snapshot.chunk_crc_le + chunk * 4, encoded,
           sizeof(encoded));
    return 1;
}

static int write_dump_chunk(int chunk, const u8 data[CHUNK_SIZE])
{
    return write_verified_range(session_paths.rom, chunk * CHUNK_SIZE,
                                data, CHUNK_SIZE);
}

static void checksum_block(u8 block[16])
{
    unsigned int sum = 0;
    int index;

    /* SCMD 42 stores the first 15 bytes plus their sum. */
    for (index = 0; index < 15; index++)
        sum += block[index];
    block[15] = (u8)sum;
}

static void prepare_stage_block(int index, u32 rom_address,
                                u16 nvram_word, int word_count,
                                u8 block[16])
{
    const struct worker_layout *layout = active_worker_layout;

    /* These blocks describe the asynchronous NVRAM worker. */
    memcpy(block, config_window[index], 16);
    if (index == layout->flags_block) {
        block[layout->flags_byte] &= WORKER_FLAGS_IDLE_MASK;
        if (clear_unused_source_bytes) {
            /* Remove stale bytes from the other candidate pointer field. */
            if (layout->source_pointer_offset == 6) {
                block[10] = 0;
                block[11] = 0;
            } else if (layout->source_pointer_offset == 7) {
                block[6] = 0;
                block[11] = 0;
            } else if (layout->source_pointer_offset == 8) {
                block[6] = 0;
                block[7] = 0;
            }
        }
        block[layout->source_pointer_offset] = (u8)rom_address;
        block[layout->source_pointer_offset + 1] = (u8)(rom_address >> 8);
        block[layout->source_pointer_offset + 2] = (u8)(rom_address >> 16);
        block[layout->source_pointer_offset + 3] = (u8)(rom_address >> 24);
    }
    if (index == layout->control_block) {
        block[layout->source_offset_byte] = 0;
        block[layout->word_count_byte] = (u8)word_count;
        block[layout->worker_state_byte] = WORKER_ARM_VALUE;
    }
    if (index == layout->destination_block) {
        block[layout->destination_low_byte] = (u8)nvram_word;
        if (layout->destination_high_byte < 15) {
            block[layout->destination_high_byte] =
                (u8)(nvram_word >> 8);
        } else {
            /* Make the checksum byte double as the destination high byte. */
            block[layout->checksum_adjust_byte] = 0;
            checksum_block(block);
            block[layout->checksum_adjust_byte] =
                (u8)(((u8)(nvram_word >> 8)) - block[15]);
        }
    }
    checksum_block(block);
}

static int send_config_block(const u8 block[16])
{
    u8 output[16];
    int transport = apply_scmd(SCMD_WRITE_CONFIG, block, 16, output);

    last_copy_transport = transport;
    last_copy_command_status = transport ? output[0] : -1;
    return transport && output[0] == 0;
}

static int wait_for_worker_and_close(void)
{
    int attempt;

    for (attempt = 0; attempt < 1000; attempt++) {
        int status = close_config();
        last_copy_close_attempts = attempt + 1;
        last_copy_close_status = status;
        if (status == 0)
            return 1;
        if (status != 1)
            return 0;
        usleep(1000);
    }
    return 0;
}

static enum copy_result copy_rom_words(u32 rom_address, u16 nvram_word,
                                       int word_count)
{
    const u8 open_parameters[3] = {
        0x01, TARGET_CONFIG_REGION, 0x00
    };
    u8 saved_flags_block[16];
    u8 block[16];
    u8 output[16];
    int index;
    int trigger_ok;
    int open_transport;

    last_copy_stage = "argument-check";
    last_copy_block = -1;
    last_copy_transport = -1;
    last_copy_command_status = -1;
    last_copy_close_status = -1;
    last_copy_close_attempts = 0;

    if (!active_worker_layout || word_count <= 0 ||
        word_count > BANK_WORDS ||
        nvram_word + word_count > NVRAM_WORDS)
        return COPY_FAILED_SAFE;
    /* A zero block count lets SCMD 42 wrap into the worker fields. */
    last_copy_stage = "open-config";
    open_transport = apply_scmd(SCMD_OPEN_CONFIG, open_parameters,
                                sizeof(open_parameters), output);
    last_copy_transport = open_transport;
    last_copy_command_status = open_transport ? output[0] : -1;
    if (!open_transport || output[0] != 0)
        return COPY_FAILED_SAFE;

    for (index = 0; index < 16; index++) {
        last_copy_stage = "stage-first-lap";
        last_copy_block = index;
        prepare_stage_block(index, rom_address, nvram_word,
                            word_count, block);
        if (index == active_worker_layout->flags_block)
            memcpy(saved_flags_block, block, sizeof(saved_flags_block));
        if (!send_config_block(block)) {
            return wait_for_worker_and_close() ?
                   COPY_FAILED_SAFE : COPY_WORKER_UNKNOWN;
        }
    }

    for (index = 0; index < active_worker_layout->flags_block; index++) {
        last_copy_stage = "stage-second-lap";
        last_copy_block = index;
        memcpy(block, config_window[index], sizeof(block));
        checksum_block(block);
        if (!send_config_block(block)) {
            return wait_for_worker_and_close() ?
                   COPY_FAILED_SAFE : COPY_WORKER_UNKNOWN;
        }
    }

    memcpy(block, saved_flags_block, sizeof(block));
    last_copy_stage = "trigger";
    last_copy_block = active_worker_layout->flags_block;
    block[active_worker_layout->flags_byte] =
        (block[active_worker_layout->flags_byte] &
         WORKER_FLAGS_IDLE_MASK) | WORKER_FLAGS_TRIGGER;
    checksum_block(block);
    trigger_ok = send_config_block(block);
    /* Never touch NVRAM while the worker state is unknown. */
    if (!wait_for_worker_and_close()) {
        last_copy_stage = "wait-close";
        return COPY_WORKER_UNKNOWN;
    }
    if (!trigger_ok)
        return COPY_FAILED_SAFE;

    for (index = 0; index < word_count; index++) {
        u16 value;
        last_copy_stage = "read-copy-destination";
        last_copy_block = nvram_word + index;
        if (!read_nvram_word(nvram_word + index, &value))
            return COPY_FAILED_SAFE;
        /* SPC970 ROM order is low byte then high byte. */
        chunk_buffer[index * 2] = (u8)value;
        chunk_buffer[index * 2 + 1] = (u8)(value >> 8);
    }
    last_copy_stage = "complete";
    last_copy_block = -1;
    return COPY_SUCCEEDED;
}

static enum copy_result run_restored_validation_attempt(
    struct validation_attempt_result *saved_result, u32 source_address,
    u16 destination_word, const u8 *expected, int expected_size,
    const char *mismatch_reason)
{
    const struct worker_layout *saved_layout = active_worker_layout;
    const struct worker_layout *observed_layout;
    enum copy_result copy_status = COPY_FAILED_SAFE;
    enum copy_result result = COPY_FAILED_SAFE;
    int word_count = sizeof(validation_observed) / 2;
    int byte_count = word_count * 2;
    int data_matches = 0;

    reset_validation_diagnostics();
    if (!read_config_window()) {
        validation_failure_reason = "config-reread-failed";
        goto finished;
    }
    observed_layout = detect_worker_layout();
    if (!observed_layout || observed_layout != saved_layout) {
        validation_failure_reason = "layout-changed-before-copy";
        goto finished;
    }

    clear_unused_source_bytes = 1;
    copy_status = copy_rom_words(source_address, destination_word,
                                 word_count);
    clear_unused_source_bytes = 0;

    if (copy_status == COPY_WORKER_UNKNOWN) {
        validation_failure_reason = "copy-worker-unknown";
        result = COPY_WORKER_UNKNOWN;
        goto finished;
    }
    if (copy_status == COPY_SUCCEEDED) {
        memcpy(validation_observed, chunk_buffer, byte_count);
        validation_observed_valid = 1;
        data_matches = memcmp(validation_observed, expected,
                              expected_size) == 0;
        validation_signature_matches = data_matches;
        validation_failure_reason = "pending-restore";
    } else {
        validation_failure_reason = "copy-failed";
    }

    validation_restore_succeeded = restore_validation_nvram();
    if (!validation_restore_succeeded) {
        validation_failure_reason = "nvram-restore-failed";
        goto finished;
    }
    validation_post_read_succeeded = read_nvram();
    if (!validation_post_read_succeeded) {
        validation_failure_reason = "post-restore-read-failed";
        goto finished;
    }
    validation_post_matches = nvram_matches_baseline();
    if (!validation_post_matches) {
        validation_failure_reason = "post-restore-mismatch";
        goto finished;
    }
    if (copy_status != COPY_SUCCEEDED) {
        validation_failure_reason = "copy-failed";
        goto finished;
    }
    if (!data_matches) {
        validation_failure_reason = mismatch_reason;
        goto finished;
    }
    validation_failure_reason = "passed";
    result = COPY_SUCCEEDED;

finished:
    clear_unused_source_bytes = 0;
    active_worker_layout = saved_layout;
    save_validation_attempt(saved_result, source_address, destination_word,
                            copy_status, data_matches);
    return result;
}

static u32 rom_entry_candidate_address(int index)
{
    /* Marker 01 is already proven at FD0000; avoid an unnecessary FC probe. */
    if (is_shifted_marker_01_layout())
        return index == 0 ? ALTERNATE_ROM_ENTRY_ADDRESS : TARGET_ROM_START;
    return index == 0 ? TARGET_ROM_START : ALTERNATE_ROM_ENTRY_ADDRESS;
}

static enum copy_result validate_shifted_destination_banks(void)
{
    enum copy_result result = COPY_FAILED_SAFE;
    int selected_entry_candidate = -1;
    int index;

    memset(bank_validation_results, 0, sizeof(bank_validation_results));
    memset(entry_validation_results, 0,
           sizeof(entry_validation_results));
    memset(selected_rom_entry_bytes, 0, sizeof(selected_rom_entry_bytes));
    selected_rom_entry_address = 0;
    selected_rom_entry_valid = 0;
    for (index = 0; index < ROM_ENTRY_CANDIDATE_COUNT; index++) {
        entry_validation_results[index].source_address =
            rom_entry_candidate_address(index);
        entry_validation_results[index].destination_word = 0;
    }

    /* Safely discover whether this revision enters ROM at FC0000 or FD0000. */
    for (index = 0; index < ROM_ENTRY_CANDIDATE_COUNT; index++) {
        u32 source_address = rom_entry_candidate_address(index);

        result = run_restored_validation_attempt(
            &entry_validation_results[index], source_address, 0,
            rom_entry_signature, sizeof(rom_entry_signature),
            "rom-signature-mismatch");
        if (result == COPY_SUCCEEDED) {
            selected_entry_candidate = index;
            selected_rom_entry_address = source_address;
            memcpy(selected_rom_entry_bytes,
                   entry_validation_results[index].observed,
                   sizeof(selected_rom_entry_bytes));
            selected_rom_entry_valid = 1;
            break;
        }
        if (result == COPY_WORKER_UNKNOWN)
            return result;
        /* Only a cleanly restored signature miss justifies another address. */
        if (entry_validation_results[index].copy_status != COPY_SUCCEEDED ||
            !entry_validation_results[index].restore_succeeded ||
            !entry_validation_results[index].post_restore_matches)
            return result;
    }
    if (selected_entry_candidate < 0) {
        validation_failure_reason = "rom-entry-not-found";
        return COPY_FAILED_SAFE;
    }

    for (index = 0; index < BANK_VALIDATION_COUNT; index++) {
        bank_validation_results[index].source_address =
            selected_rom_entry_address;
        bank_validation_results[index].destination_word =
            bank_destination_words[index];
    }

    /* The successful entry probe already proves destination bank zero. */
    bank_validation_results[0] =
        entry_validation_results[selected_entry_candidate];
    bank_validation_results[0].data_matches = 1;

    for (index = 1; index < BANK_VALIDATION_COUNT; index++) {
        result = run_restored_validation_attempt(
            &bank_validation_results[index],
            selected_rom_entry_address,
            bank_destination_words[index],
            selected_rom_entry_bytes, sizeof(selected_rom_entry_bytes),
            "rom-data-mismatch");
        if (result != COPY_SUCCEEDED)
            return result;
    }
    return COPY_SUCCEEDED;
}

static enum copy_result validate_worker_layout(void)
{
    const struct worker_layout *observed_layout;
    enum copy_result copy_status;

    /* Prove the selected offsets with a small copy and full restoration. */
    reset_validation_diagnostics();
    if (!read_config_window()) {
        validation_failure_reason = "config-reread-failed";
        return COPY_FAILED_SAFE;
    }
    observed_layout = detect_worker_layout();
    if (!observed_layout || observed_layout != active_worker_layout) {
        validation_failure_reason = "layout-changed-before-copy";
        return COPY_FAILED_SAFE;
    }
    copy_status = copy_rom_words(TARGET_ROM_START, 0, 8);
    if (copy_status == COPY_WORKER_UNKNOWN) {
        validation_failure_reason = "copy-worker-unknown";
        return copy_status;
    }
    if (copy_status == COPY_SUCCEEDED) {
        memcpy(validation_observed, chunk_buffer,
               sizeof(validation_observed));
        validation_observed_valid = 1;
        validation_signature_matches =
            memcmp(validation_observed, rom_entry_signature,
                   sizeof(rom_entry_signature)) == 0;
        validation_failure_reason = validation_signature_matches ?
            "pending-restore" : "rom-signature-mismatch";
    } else {
        validation_failure_reason = "copy-failed";
    }

    /* Repair any unintended destination as well as the validation range. */
    validation_restore_succeeded = restore_validation_nvram();
    if (!validation_restore_succeeded) {
        validation_failure_reason = "nvram-restore-failed";
        return COPY_FAILED_SAFE;
    }
    validation_post_read_succeeded = read_nvram();
    if (!validation_post_read_succeeded) {
        validation_failure_reason = "post-restore-read-failed";
        return COPY_FAILED_SAFE;
    }
    validation_post_matches = nvram_matches_baseline();
    if (!validation_post_matches) {
        validation_failure_reason = "post-restore-mismatch";
        return COPY_FAILED_SAFE;
    }
    if (copy_status != COPY_SUCCEEDED) {
        validation_failure_reason = "copy-failed";
        return COPY_FAILED_SAFE;
    }
    if (!validation_signature_matches) {
        validation_failure_reason = "rom-signature-mismatch";
        return COPY_FAILED_SAFE;
    }
    validation_failure_reason = "passed";
    return COPY_SUCCEEDED;
}

static int crc32_dump(u32 *result)
{
    u32 crc = 0xffffffffu;
    u8 buffer[1024];
    int remaining = TARGET_ROM_SIZE;
    int file_descriptor = open(session_paths.rom, O_RDONLY);

    if (file_descriptor < 0)
        return 0;
    while (remaining > 0) {
        int count = read(file_descriptor, buffer,
                         remaining > (int)sizeof(buffer) ?
                         (int)sizeof(buffer) : remaining);
        if (count <= 0) {
            close(file_descriptor);
            return 0;
        }
        crc = update_crc32(crc, buffer, count);
        remaining -= count;
    }
    if (close(file_descriptor) < 0)
        return 0;
    *result = ~crc;
    return 1;
}

static void clear_screen(u32 background, int x, int y)
{
    scr_setbgcolor(background);
    scr_setfontcolor(0xffffffff);
    scr_setCursor(0);
    scr_clear();
    scr_setXY(x, y);
}

static int session_can_start(enum session_state state)
{
    return state == SESSION_NO_SESSION || state == SESSION_VALID_SESSION ||
           (state == SESSION_INCOMPLETE_FILES && session_setup_ready);
}

static int confirm_empty_stopped_drive(void)
{
    int buttons_released = 0;

    clear_screen(0x00202000, 4, 4);
    scr_printf("%s\n\n", PROJECT_NAME);
    scr_printf("DISC DRIVE CHECK\n\n");
    scr_printf("REMOVE ANY DISC AND CLOSE THE TRAY.\n");
    scr_printf("WAIT FOR THE DRIVE TO STOP.\n\n");
    scr_printf("X  CONTINUE\n");
    scr_printf("CIRCLE  EXIT\n");

    if (!open_controller())
        return 0;
    for (;;) {
        u16 pressed_buttons = read_pressed_buttons();

        if ((pressed_buttons & (PAD_CROSS | PAD_CIRCLE)) == 0)
            buttons_released = 1;
        if (buttons_released && (pressed_buttons & PAD_CIRCLE))
            return 0;
        if (buttons_released && (pressed_buttons & PAD_CROSS)) {
            scr_setXY(4, 14);
            scr_printf("WAITING FOR THE DRIVE TO SETTLE...\n");
            usleep(DRIVE_SETTLE_US);
            return 1;
        }
        usleep(16000);
    }
}

static int menu_can_start(enum restore_source source,
                          enum session_state state)
{
    return active_worker_layout && source == RESTORE_NONE &&
           session_can_start(state);
}

static void draw_session_summary(enum session_state state)
{
    if (active_session_slot == LEGACY_SESSION_SLOT)
        scr_printf("SESSION SLOT: LEGACY UNNUMBERED FILES\n");
    else if (active_session_slot >= 0)
        scr_printf("SESSION SLOT: %03d\n", active_session_slot);

    switch (state) {
        case SESSION_NO_SESSION:
            scr_printf("SESSION: NO SAVED DUMP\n");
            break;
        case SESSION_VALID_SESSION:
            if (session_snapshot.completed_chunks == MAX_CHUNK_COUNT)
                scr_printf("SESSION: COMPLETE DUMP READY\n");
            else
                scr_printf("SESSION: RESUME READY (%d / %d CHUNKS)\n",
                           session_snapshot.completed_chunks,
                           MAX_CHUNK_COUNT);
            break;
        case SESSION_INCOMPLETE_FILES:
            if (session_setup_ready)
                scr_printf("SESSION: SAFE SETUP READY TO CONTINUE\n");
            else
                scr_printf("SESSION ERROR: FILES MISSING OR INCOMPLETE\n");
            break;
        case SESSION_INCOMPATIBLE_FORMAT:
            scr_printf("SESSION ERROR: FORMAT NOT SUPPORTED\n");
            break;
        case SESSION_CORRUPT_METADATA:
            scr_printf("SESSION ERROR: METADATA DAMAGED\n");
            break;
        case SESSION_MIXED_FILES:
            scr_printf("SESSION ERROR: FILES ARE FROM DIFFERENT SESSIONS\n");
            break;
        case SESSION_DIFFERENT_CONSOLE:
            scr_printf("SESSION BLOCKED: UNFINISHED DUMP DOES NOT MATCH\n");
            break;
        case SESSION_AMBIGUOUS_SESSIONS:
            scr_printf("SESSION ERROR: MULTIPLE DUMPS MATCH THIS PS2\n");
            break;
        case SESSION_SLOTS_FULL:
            scr_printf("SESSION ERROR: ALL 100 DUMP SLOTS ARE OCCUPIED\n");
            break;
        case SESSION_CORRUPT_ROM_CHUNKS:
            scr_printf("SESSION ERROR: ROM CHUNK %d FAILED CRC CHECK\n",
                       session_snapshot.corrupt_chunk);
            break;
    }
}

static void draw_start_menu(enum restore_source source,
                            enum session_state session_state)
{
    clear_screen(0x00400000, 4, 4);
    scr_printf("%s\n\n", PROJECT_NAME);
    scr_printf("CONSOLE: %s\n", console_name);
    scr_printf("SAFETY CAPTURE: SAVED AND VERIFIED\n");
    if (!active_worker_layout)
        scr_printf("LAYOUT: UNKNOWN OR UNSUPPORTED\n");
    else
        scr_printf("LAYOUT: %s\n", active_worker_layout->name);
    draw_session_summary(session_state);
    if (active_worker_layout &&
        active_worker_layout->destination_high_byte == 15 &&
        (session_state == SESSION_NO_SESSION || session_setup_ready))
        scr_printf("VALIDATION: ROM ENTRY AND ALL FOUR NVRAM BANKS\n");
    scr_printf("NVRAM: RESTORED AND VERIFIED AFTER DUMP\n");
    if (source == RESTORE_SESSION)
        scr_printf("RECOVERY: SESSION NVRAM BACKUP READY\n");
    else if (source == RESTORE_NUMBERED)
        scr_printf("RECOVERY: NVRAM%02d_RESTORE.BIN READY\n", restore_slot);
    else if (source == RESTORE_INVALID)
        scr_printf("RECOVERY ERROR: INVALID RESTORE REQUEST\n");
    if (invalid_restore_marker && source != RESTORE_INVALID)
        scr_printf("NUMBERED RESTORE ERROR: INVALID REQUEST\n");
    if (menu_can_start(source, session_state)) {
        if (session_state == SESSION_NO_SESSION)
            scr_printf("\nX  START NEW DUMP\n");
        else if (session_setup_ready)
            scr_printf("\nX  CONTINUE SAFE SETUP\n");
        else if (session_snapshot.completed_chunks == MAX_CHUNK_COUNT)
            scr_printf("\nX  VERIFY COMPLETED DUMP\n");
        else
            scr_printf("\nX  RESUME DUMP\n");
    } else if (!active_worker_layout) {
        scr_printf("\nDUMPING IS NOT SUPPORTED ON THIS LAYOUT.\n");
    } else if (session_state == SESSION_DIFFERENT_CONSOLE) {
        scr_printf("\nBACK UP OR FINISH THIS SESSION BEFORE CONTINUING.\n");
    } else if (session_state == SESSION_AMBIGUOUS_SESSIONS) {
        scr_printf("\nREVIEW THE MATCHING SESSION FILES ON USB.\n");
    } else if (session_state == SESSION_SLOTS_FULL) {
        scr_printf("\nBACK UP USB FILES AND FREE A COMPLETE DUMP SLOT.\n");
    } else if (source == RESTORE_SESSION || source == RESTORE_NUMBERED) {
        scr_printf("\nRESTORE NVRAM BEFORE DUMPING.\n");
    } else if (source == RESTORE_INVALID) {
        scr_printf("\nFIX THE RESTORE REQUEST ON USB.\n");
    } else {
        scr_printf("\nFIX THE SESSION FILES ON USB.\n");
    }
    if (source == RESTORE_SESSION || source == RESTORE_NUMBERED)
        scr_printf("SQUARE  RESTORE NVRAM\n");
    scr_printf("CIRCLE  EXIT\n");
    scr_printf("\nWARNING: BACK UP EVERY USB FILE.\n");
}

static enum startup_action show_start_menu(enum restore_source source,
                                            enum session_state session_state)
{
    int buttons_released = 0;
    enum startup_action action = STARTUP_STOP;

    draw_start_menu(source, session_state);

    if (!open_controller())
        return STARTUP_STOP;
    for (;;) {
        u16 pressed_buttons = read_pressed_buttons();

        if ((pressed_buttons &
             (PAD_CROSS | PAD_SQUARE | PAD_CIRCLE)) == 0)
            buttons_released = 1;
        if (buttons_released && (pressed_buttons & PAD_CIRCLE))
            break;
        if (buttons_released && (pressed_buttons & PAD_CROSS) &&
            active_worker_layout &&
            menu_can_start(source, session_state)) {
            action = STARTUP_DUMP;
            break;
        }
        if (buttons_released && (pressed_buttons & PAD_SQUARE) &&
            (source == RESTORE_SESSION ||
             source == RESTORE_NUMBERED)) {
            action = STARTUP_RESTORE;
            break;
        }
        usleep(16000);
    }
    return action;
}

static void draw_start_hold_progress(int held_ticks)
{
    char bar[START_HOLD_BAR_WIDTH + 3];
    int filled = held_ticks * START_HOLD_BAR_WIDTH / START_HOLD_TICKS;
    int remaining_ticks = START_HOLD_TICKS - held_ticks;
    int remaining_tenths = (remaining_ticks * 10 + 59) / 60;
    int index;

    bar[0] = '[';
    for (index = 0; index < START_HOLD_BAR_WIDTH; index++)
        bar[index + 1] = index < filled ? '#' : '-';
    bar[START_HOLD_BAR_WIDTH + 1] = ']';
    bar[START_HOLD_BAR_WIDTH + 2] = '\0';

    scr_setXY(16, 13);
    scr_printf("%s  %d.%d SECONDS  \n", bar,
               remaining_tenths / 10, remaining_tenths % 10);
}

static int wait_before_dump(void)
{
    const u16 shortcut = PAD_L1 | PAD_L2 | PAD_R1 | PAD_R2 |
                         PAD_LEFT | PAD_CROSS;
    int held_ticks = 0;
    int last_display_key = -1;

    clear_screen(0x00002040, 4, 5);
    scr_printf("DUMP START CONFIRMATION\n\n");
    scr_printf("DO NOT RESET DURING VALIDATION OR DUMPING.\n");
    scr_printf("WAIT FOR THE FINAL RESULT SCREEN.\n\n");
    scr_printf("HOLD X FOR FIVE SECONDS. RELEASE RESETS THE BAR.\n");
    scr_printf("CIRCLE  CANCEL\n");
    draw_start_hold_progress(0);

    while (held_ticks < START_HOLD_TICKS) {
        u16 pressed_buttons = read_pressed_buttons();
        int display_key;

        if (pressed_buttons & PAD_CIRCLE)
            return 0;
        if ((pressed_buttons & shortcut) == shortcut)
            return 1;
        if (pressed_buttons & PAD_CROSS)
            held_ticks++;
        else
            held_ticks = 0;

        display_key = (held_ticks * START_HOLD_BAR_WIDTH /
                       START_HOLD_TICKS) * 100 +
                      ((START_HOLD_TICKS - held_ticks) * 10 + 59) / 60;
        if (display_key != last_display_key) {
            draw_start_hold_progress(held_ticks);
            last_display_key = display_key;
        }
        usleep(16667);
    }
    scr_setXY(16, 15);
    scr_printf("STARTING...\n");
    return 1;
}

static int confirm_nvram_restore(enum restore_source source)
{
    clear_screen(0x00002040, 4, 4);
    scr_printf("RESTORE ALL NVRAM?\n\n");
    scr_printf("SOURCE: %s\n",
               source == RESTORE_SESSION ? "SESSION BACKUP" :
               "NUMBERED BACKUP");
    scr_printf("BACKUP MODEL: %s\n", restore_model);
    scr_printf("CRC32: %08lX\n\n",
               (unsigned long)crc32_bytes(restore_nvram, NVRAM_BYTES));
    scr_printf("HOLD L1+R1 AND PRESS X TO RESTORE.\n");
    scr_printf("PRESS CIRCLE TO CANCEL.\n");
    return wait_for_hold_confirmation();
}

static void show_nvram_verified(void)
{
    clear_screen(0x00003000, 4, 6);
    scr_printf("NVRAM RESTORED AND VERIFIED\n\n");
    scr_printf("SAVING POST-RESTORE CAPTURE...\n");
    scr_printf("DO NOT RESET YET.\n");
}

static void show_restore_result(int restored, int post_capture_saved)
{
    clear_screen(restored ? 0x00003000 : 0x00000040, 4, 4);
    scr_printf("NVRAM RESTORE\n\n");
    scr_printf("RESULT: %s\n",
               restored ? "RESTORED AND VERIFIED" : "FAILED");
    scr_printf("POST-RESTORE CAPTURE: %s\n",
               post_capture_saved ? "VERIFIED" : "NOT SAVED");
    if (strcmp(capture_failure_reason, "capture-slots-full") == 0)
        scr_printf("ALL 100 CAPTURE SLOTS (00-99) ARE OCCUPIED.\n");
    if (restored)
        scr_printf("BACKUP FILE: UNCHANGED\n");
    else {
        scr_printf("NVRAM MAY STILL REQUIRE RECOVERY.\n");
        scr_printf("RESET AND CHOOSE SQUARE AGAIN.\n");
    }
    if (restore_status_saved)
        scr_printf("\nCHECK NVRAM_RESTORE.TXT ON USB.\n");
    else
        scr_printf("\nRESTORE REPORT COULD NOT BE SAVED.\n");
    scr_printf("RESET WHEN READY.\n");
}

static void show_restore_required(void)
{
    clear_screen(0x00000040, 4, 5);
    scr_printf("NVRAM RESTORE REQUIRED\n\n");
    scr_printf("SAVED ROM DATA IS SAFE.\n");
    scr_printf("RESET, THEN CHOOSE SQUARE.\n");
}

static int perform_nvram_restore(enum restore_source source)
{
    int post_capture_saved = 0;
    int restored;

    if (!confirm_nvram_restore(source)) {
        write_restore_status("restore-declined", source, 0);
        clear_screen(0x00002040, 4, 6);
        scr_printf("NVRAM RESTORE CANCELED\n\n");
        scr_printf("NO NVRAM WAS WRITTEN.\n");
        if (!restore_status_saved)
            scr_printf("RESTORE REPORT COULD NOT BE SAVED.\n");
        scr_printf("RESET WHEN READY.\n");
        return 0;
    }

    /* Change screens before USB access so acceptance is unmistakable. */
    clear_screen(0x00000000, 4, 6);
    scr_printf("RESTORING NVRAM\n\n");
    scr_printf("DO NOT RESET WHILE RESTORING.\n");
    if (restore_dirty_bank_mask)
        scr_printf("RESTORING CHANGED NVRAM WORDS.\n");
    else
        scr_printf("NVRAM ALREADY MATCHES BACKUP.\n");
    restored = (!restore_dirty_bank_mask ||
                restore_nvram_words_with_progress(
                    restore_nvram, 0, NVRAM_WORDS)) &&
               memcmp(nvram_image, restore_nvram, NVRAM_BYTES) == 0;
    if (restored) {
        show_nvram_verified();
        identify_console();
        post_capture_saved = save_capture();
    }

    write_restore_status(restored ? "complete" :
                         "restore-failed",
                         source, post_capture_saved);
    show_restore_result(restored, post_capture_saved);
    return restored;
}

static void show_progress(int chunk)
{
    clear_screen(0x00202000, 4, 6);
    scr_printf("%s ROM DUMP\n\n", console_name);
    scr_printf("CHUNK %d / %d\n\n", chunk + 1,
               MAX_CHUNK_COUNT);
    scr_printf("NVRAM WILL BE RESTORED AFTER DUMPING.\n\n");
    scr_printf("DO NOT RESET WHILE DUMPING.\n");
}

static void show_dump_restore(int completed_chunks)
{
    clear_screen(0x00000000, 4, 6);
    scr_printf("RESTORING NVRAM\n\n");
    scr_printf("ROM CHUNKS SAVED: %d / %d\n\n",
               completed_chunks, MAX_CHUNK_COUNT);
    scr_printf("DO NOT RESET WHILE RESTORING.\n");
}

static void show_result(int dump_succeeded, int completed_chunks, u32 crc,
                        int worker_state_unknown)
{
    clear_screen(dump_succeeded ? 0x00003000 : 0x00000040, 4, 4);
    scr_printf("%s ROM DUMP\n\n", console_name);
    scr_printf("RESULT: %s\n",
               dump_succeeded ? "COMPLETE" : "NOT COMPLETE");
    scr_printf("CHUNKS: %d / %d\n", completed_chunks,
               MAX_CHUNK_COUNT);
    scr_printf("SAFETY CAPTURE: %s\n",
               capture_saved && strcmp(capture_failure_reason, "none") == 0 ?
               "VERIFIED" : "FAILED");
    if (strcmp(capture_failure_reason, "capture-slots-full") == 0)
        scr_printf("ALL 100 CAPTURE SLOTS (00-99) ARE OCCUPIED.\n");
    if (dump_succeeded)
        scr_printf("CRC32: %08lX\n", (unsigned long)crc);
    if (worker_state_unknown)
        scr_printf("\nWORKER STATE UNKNOWN. RESET BEFORE RERUNNING.\n");
    else if (!dump_status_saved)
        scr_printf("\nSTATUS REPORT COULD NOT BE SAVED.\n");
    else if (strcmp(validation_failure_reason, "not-run") != 0 &&
             strcmp(validation_failure_reason, "passed") != 0)
        scr_printf("\nCHECK %s ON USB.\n", validation_status_name);
    else if (session_reserved)
        scr_printf("\nCHECK %s ON USB.\n", session_status_name);
    else
        scr_printf("\nCHECK SPC970_STATUS.TXT ON USB.\n");
    scr_printf("BACK UP USB FILES BEFORE DELETING THEM.\n");
    scr_printf("RESET WHEN READY.\n");
}

int main(void)
{
    enum restore_source available_restore = RESTORE_NONE;
    enum startup_action startup_choice;
    int completed_chunks = 0;
    int validate_new_session = 0;
    int worker_state_unknown = 0;
    int chunk;
    int dump_succeeded = 0;
    int nvram_restored = 0;
    const char *stop_state = "stopped";
    u32 final_crc32 = 0;

    SifInitRpc(0);
    init_scr();
    printf("%s built %s %s\n", PROJECT_NAME, BUILD_DATE, BUILD_TIME);
    if (!confirm_empty_stopped_drive()) {
        close_controller();
        clear_screen(0x00202000, 4, 6);
        scr_printf("STOPPED\n\n");
        scr_printf("NO CONSOLE DATA WAS CHANGED.\n");
        scr_printf("RESET WHEN READY.\n");
        SleepThread();
        return 0;
    }

    clear_screen(0x00202000, 4, 6);
    scr_printf("INITIALIZING DISC DRIVE...\n");
    if (!sceCdInit(SCECdINoD))
        goto preflight_failed;

    clear_screen(0x00202000, 4, 6);
    scr_printf("INITIALIZING USB STORAGE...\n");
    if (!init_usb_storage(USB_DIR))
        goto preflight_failed;

    clear_screen(0x00202000, 4, 6);
    scr_printf("READING CONSOLE SAFETY DATA...\n");
    if (!read_version() || !read_config_window() || !read_nvram())
        goto preflight_failed;

    active_worker_layout = detect_worker_layout();
    identify_console();
    initialize_session_profile();

    /* The read-only capture must finish before any write is allowed. */
    clear_screen(0x00202000, 4, 6);
    scr_printf("SAVING SAFETY CAPTURE\n\n");
    scr_printf("DO NOT REMOVE THE USB DRIVE.\n");
    if (!save_capture())
        goto preflight_failed;
    capture_saved = 1;

    select_session_slot();
    available_restore = detect_restore_source();
    startup_choice = show_start_menu(available_restore,
                                     current_session_state);
    if (startup_choice == STARTUP_RESTORE) {
        int restore_succeeded = perform_nvram_restore(available_restore);
        SleepThread();
        return restore_succeeded ? 0 : 1;
    }
    if (startup_choice != STARTUP_DUMP) {
        int saved_chunks = current_session_state == SESSION_VALID_SESSION ?
                           session_snapshot.completed_chunks : 0;

        close_controller();
        session_reserved = 0;
        write_status("stopped-at-menu", -1, saved_chunks, 0, 0);
        clear_screen(0x00202000, 4, 6);
        scr_printf("STOPPED\n\n");
        scr_printf("NO CONSOLE DATA WAS CHANGED.\n");
        scr_printf("USB SESSION FILES WERE LEFT IN PLACE.\n");
        scr_printf("RESET WHEN READY.\n");
        SleepThread();
        return 0;
    }

    if (!config_window_is_extended() || !active_worker_layout ||
        !session_can_start(current_session_state)) {
        close_controller();
        goto preflight_failed;
    }
    if (!wait_before_dump()) {
        close_controller();
        write_status("stopped-during-countdown", -1, 0, 0, 0);
        clear_screen(0x00202000, 4, 6);
        scr_printf("STOPPED\n\n");
        scr_printf("START CONFIRMATION WAS CANCELED.\n");
        scr_printf("NO CONSOLE DATA WAS CHANGED.\n");
        scr_printf("USB SESSION FILES WERE LEFT IN PLACE.\n");
        scr_printf("RESET WHEN READY.\n");
        SleepThread();
        return 0;
    }
    validate_new_session = current_session_state == SESSION_NO_SESSION ||
                           session_setup_ready;
    close_controller();

    if (validate_new_session) {
        enum copy_result validation_status;
        int bank_validation =
            active_worker_layout->destination_high_byte == 15;

        clear_screen(0x00000000, 4, 6);
        scr_printf("PREPARING SAFE DUMP\n\n");
        if (session_setup_ready)
            scr_printf("USING VERIFIED NVRAM RECOVERY BASELINE...\n");
        else
            scr_printf("SAVING NVRAM RECOVERY BASELINE...\n");
        scr_printf("DO NOT RESET.\n");
        if (!session_setup_ready) {
            if (!prepare_session_baseline()) {
                refresh_session_state();
                write_status("recovery-baseline-save-failed", -1, 0, 0, 0);
                goto stopped;
            }
            refresh_session_state();
        }
        write_status("validating-worker-layout", -1, 0, 0, 0);
        clear_screen(0x00000000, 4, 6);
        scr_printf("VALIDATING ROM ACCESS\n\n");
        if (bank_validation)
            scr_printf("CHECKING AND RESTORING ALL FOUR NVRAM BANKS.\n");
        else
            scr_printf("CHECKING ROM ACCESS AND RESTORING NVRAM.\n");
        scr_printf("DO NOT RESET.\n");
        validation_status = bank_validation ?
            validate_shifted_destination_banks() :
            validate_worker_layout();
        if (!(bank_validation ? write_bank_validation_report() :
              write_validation_report(validation_status))) {
            worker_state_unknown =
                validation_status == COPY_WORKER_UNKNOWN;
            write_status(worker_state_unknown ? "worker-state-unknown" :
                         "validation-report-save-failed", -1, 0, 0, 0);
            goto stopped_with_worker_state;
        }
        if (validation_status != COPY_SUCCEEDED) {
            worker_state_unknown = validation_status == COPY_WORKER_UNKNOWN;
            write_status(worker_state_unknown ? "worker-state-unknown" :
                         "worker-layout-validation-failed", -1, 0, 0, 0);
            goto stopped_with_worker_state;
        }
        if (!create_session_files()) {
            refresh_session_state();
            write_status("session-create-failed", -1, 0, 0, 0);
            goto stopped;
        }
    }

    if (!load_session(&completed_chunks))
        goto preflight_failed;
    if (!nvram_matches_baseline()) {
        write_status("restore-required", -1,
                     completed_chunks, 0, 0);
        show_restore_required();
        SleepThread();
        return 1;
    }
    write_status("running",
                 completed_chunks < MAX_CHUNK_COUNT ? completed_chunks : -1,
                 completed_chunks, 0, 0);

    for (chunk = completed_chunks;
         chunk < MAX_CHUNK_COUNT; chunk++) {
        int bank = chunk % BANK_COUNT;
        u16 nvram_word = bank * BANK_WORDS;
        u32 rom_address = TARGET_ROM_START + chunk * CHUNK_SIZE;
        enum copy_result copy_status;
        int rom_chunk_saved;
        const struct worker_layout *observed_layout;

        if (!read_config_window()) {
            stop_state = "config-read-failed";
            write_status("config-read-failed", chunk, completed_chunks, 0, 0);
            break;
        }
        observed_layout = detect_worker_layout();
        if (!observed_layout || observed_layout != active_worker_layout) {
            stop_state = "worker-layout-changed";
            write_status("worker-layout-changed", chunk,
                         completed_chunks, 0, 0);
            break;
        }
        show_progress(chunk);
        copy_status = copy_rom_words(rom_address, nvram_word, BANK_WORDS);
        if (copy_status == COPY_WORKER_UNKNOWN) {
            worker_state_unknown = 1;
            stop_state = "worker-state-unknown";
            write_status("worker-state-unknown", chunk, completed_chunks, 0, 0);
            break;
        }

        rom_chunk_saved = copy_status == COPY_SUCCEEDED &&
                  write_dump_chunk(chunk, chunk_buffer);
        if (!rom_chunk_saved) {
            stop_state = "chunk-failed";
            write_status("chunk-failed", chunk, completed_chunks, 0, 0);
            break;
        }
        if (!write_chunk_crc(chunk, chunk_buffer)) {
            stop_state = "chunk-crc-update-failed";
            write_status("chunk-crc-update-failed", chunk,
                         completed_chunks, 0, 0);
            break;
        }
        /* The bit is the final commit after data and CRC readback. */
        if (!mark_chunk_complete(chunk)) {
            stop_state = "map-update-failed";
            write_status("map-update-failed", chunk, completed_chunks, 0, 0);
            break;
        }
        completed_chunks = chunk + 1;
        /* The map records every chunk; the text report is less frequent. */
        if (completed_chunks % STATUS_INTERVAL_CHUNKS == 0 ||
            completed_chunks == MAX_CHUNK_COUNT)
            write_status("running",
                         completed_chunks < MAX_CHUNK_COUNT ?
                         completed_chunks : -1,
                         completed_chunks, 0, 0);
    }

    if (!worker_state_unknown) {
        show_dump_restore(completed_chunks);
        write_status("restoring-nvram", -1,
                     completed_chunks, 0, 0);
        nvram_restored = restore_nvram_words_with_progress(
                             session_nvram_baseline, 0, NVRAM_WORDS) &&
                         nvram_matches_baseline();
    }

    if (completed_chunks == MAX_CHUNK_COUNT && nvram_restored &&
        refresh_session_state() == SESSION_VALID_SESSION &&
        session_snapshot.completed_chunks == MAX_CHUNK_COUNT &&
        save_capture() &&
        crc32_dump(&final_crc32)) {
        dump_succeeded = 1;
        write_status("complete", -1, completed_chunks, final_crc32, 1);
    } else if (completed_chunks == MAX_CHUNK_COUNT) {
        const char *failure = !nvram_restored ? "nvram-restore-failed" :
                              strcmp(capture_failure_reason, "none") != 0 ?
                              capture_failure_reason :
                              current_session_state != SESSION_VALID_SESSION ?
                              session_state_name(current_session_state) :
                              "completion-check-failed";
        write_status(failure,
                     -1, completed_chunks, 0, 0);
    } else if (!worker_state_unknown) {
        write_status(nvram_restored ? stop_state : "nvram-restore-failed",
                     -1, completed_chunks, 0, 0);
    }
    show_result(dump_succeeded, completed_chunks, final_crc32, worker_state_unknown);
    SleepThread();
    return dump_succeeded ? 0 : 1;

preflight_failed:
    write_status(strcmp(capture_failure_reason, "none") != 0 ?
                 capture_failure_reason : "preflight-failed",
                 -1, completed_chunks, 0, 0);
stopped:
    show_result(0, completed_chunks, 0, 0);
    SleepThread();
    return 1;

stopped_with_worker_state:
    show_result(0, completed_chunks, 0, worker_state_unknown);
    SleepThread();
    return 1;
}

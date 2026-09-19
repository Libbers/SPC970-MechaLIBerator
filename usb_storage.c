#include "usb_storage.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <loadfile.h>
#include <sbv_patches.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <tamtypes.h>
#include <unistd.h>

#define VERIFY_BUFFER_SIZE 8192
#define REPLACE_PATH_CAPACITY 256

extern unsigned char usbd_irx[] __attribute__((aligned(16)));
extern unsigned int size_usbd_irx;
extern unsigned char usbhdfsd_irx[] __attribute__((aligned(16)));
extern unsigned int size_usbhdfsd_irx;

static u8 verify_buffer[VERIFY_BUFFER_SIZE];

int write_full(int file_descriptor, const void *data, int size)
{
    const u8 *bytes = data;
    int written = 0;

    if (size < 0 || (!data && size))
        return 0;
    while (written < size) {
        int count = write(file_descriptor, bytes + written, size - written);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return 0;
        written += count;
    }
    return 1;
}

int read_full(int file_descriptor, void *data, int size)
{
    u8 *bytes = data;
    int consumed = 0;

    if (size < 0 || (!data && size))
        return 0;
    while (consumed < size) {
        int count = read(file_descriptor, bytes + consumed, size - consumed);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return 0;
        consumed += count;
    }
    return 1;
}

int file_exists(const char *path)
{
    struct stat status;
    return stat(path, &status) == 0;
}

int file_has_size(const char *path, int size)
{
    struct stat status;
    return size >= 0 && stat(path, &status) == 0 &&
           S_ISREG(status.st_mode) && status.st_size == size;
}

int read_file_range(const char *path, int offset, void *data, int size)
{
    int file_descriptor;
    int succeeded;

    if (offset < 0 || size < 0 || size > INT_MAX - offset || (!data && size))
        return 0;
    file_descriptor = open(path, O_RDONLY);
    succeeded = file_descriptor >= 0;

    if (succeeded)
        succeeded = lseek(file_descriptor, offset, SEEK_SET) == offset &&
                    read_full(file_descriptor, data, size);
    if (file_descriptor >= 0 && close(file_descriptor) < 0)
        succeeded = 0;
    return succeeded;
}

int write_file_range(const char *path, int offset,
                     const void *data, int size)
{
    int file_descriptor;
    int succeeded;

    if (offset < 0 || size < 0 || size > INT_MAX - offset || (!data && size))
        return 0;
    file_descriptor = open(path, O_RDWR);
    succeeded = file_descriptor >= 0;

    if (succeeded)
        succeeded = lseek(file_descriptor, offset, SEEK_SET) == offset &&
                    write_full(file_descriptor, data, size);
    if (file_descriptor >= 0 && close(file_descriptor) < 0)
        succeeded = 0;
    return succeeded;
}

int read_exact_file(const char *path, void *data, int size)
{
    return file_has_size(path, size) &&
           read_file_range(path, 0, data, size);
}

int read_text_file(const char *path, char *text, int capacity)
{
    struct stat status;
    int size;

    if (!text || capacity <= 0)
        return 0;
    text[0] = 0;
    if (stat(path, &status) < 0 || status.st_size <= 0 ||
        status.st_size >= capacity)
        return 0;
    size = status.st_size;
    if (!read_exact_file(path, text, size) || memchr(text, 0, size)) {
        text[0] = 0;
        return 0;
    }
    text[size] = 0;
    return 1;
}

static int directory_ready(const char *directory)
{
    struct stat status;

    if (stat(directory, &status) == 0 && S_ISDIR(status.st_mode))
        return 1;
    if (mkdir(directory, 0777) == 0)
        return 1;
    return stat(directory, &status) == 0 && S_ISDIR(status.st_mode);
}

int init_usb_storage(const char *directory)
{
    int attempt;
    int usb_driver_result;
    int mass_storage_driver_result;

    if (directory_ready(directory))
        return 1;

    sbv_patch_enable_lmb();
    usb_driver_result = SifExecModuleBuffer(usbd_irx, size_usbd_irx,
                                            0, NULL, NULL);
    mass_storage_driver_result = SifExecModuleBuffer(
        usbhdfsd_irx, size_usbhdfsd_irx, 0, NULL, NULL);
    printf("USB modules: %d %d\n", usb_driver_result,
           mass_storage_driver_result);

    for (attempt = 0; attempt < 20; attempt++) {
        if (directory_ready(directory))
            return 1;
        usleep(250000);
    }
    return 0;
}

int write_verified_range(const char *path, int offset,
                         const void *data, int size)
{
    if (size < 0 || size > (int)sizeof(verify_buffer) ||
        !write_file_range(path, offset, data, size) ||
        !read_file_range(path, offset, verify_buffer, size))
        return 0;
    return size == 0 || memcmp(data, verify_buffer, size) == 0;
}

static int write_and_verify_file(const char *path, const void *data,
                                 int size, int create_only, int *created)
{
    int file_descriptor;
    int succeeded;

    if (created)
        *created = 0;
    if (size < 0 || size > (int)sizeof(verify_buffer) || (!data && size))
        return 0;
    file_descriptor = open(path, O_WRONLY | O_CREAT |
                           (create_only ? O_EXCL : O_TRUNC), 0666);
    if (file_descriptor < 0)
        return 0;
    if (create_only && created)
        *created = 1;
    succeeded = write_full(file_descriptor, data, size);
    if (close(file_descriptor) < 0)
        succeeded = 0;
    if (!succeeded)
        return 0;

    /* Reopen the file so cached USB write failures are caught. */
    succeeded = read_exact_file(path, verify_buffer, size);
    return succeeded && (size == 0 || memcmp(data, verify_buffer, size) == 0);
}

int write_verified_file(const char *path, const void *data, int size)
{
    return write_and_verify_file(path, data, size, 0, NULL);
}

int replace_verified_file(const char *path, const void *data, int size)
{
    char temporary_path[REPLACE_PATH_CAPACITY];
    int created = 0;
    int length;

    if (!path)
        return 0;
    length = snprintf(temporary_path, sizeof(temporary_path), "%s.TMP", path);
    if (length <= 0 || length >= (int)sizeof(temporary_path))
        return 0;
    if (file_exists(temporary_path) && unlink(temporary_path) < 0)
        return 0;
    if (!write_new_verified_file_tracked(temporary_path, data, size,
                                         &created)) {
        if (created)
            unlink(temporary_path);
        return 0;
    }
    if (file_exists(path) && unlink(path) < 0) {
        unlink(temporary_path);
        return 0;
    }
    if (rename(temporary_path, path) < 0) {
        unlink(temporary_path);
        return 0;
    }
    return read_exact_file(path, verify_buffer, size) &&
           (size == 0 || memcmp(data, verify_buffer, size) == 0);
}

int write_new_verified_file(const char *path, const void *data, int size)
{
    return write_new_verified_file_tracked(path, data, size, NULL);
}

int write_new_verified_file_tracked(const char *path, const void *data,
                                    int size, int *created)
{
    return write_and_verify_file(path, data, size, 1, created);
}

int write_new_zero_file(const char *path, int size)
{
    return write_new_zero_file_tracked(path, size, NULL);
}

int write_new_zero_file_tracked(const char *path, int size, int *created)
{
    static const u8 zeros[4096] = {0};
    int file_descriptor;
    int offset;
    int succeeded = size >= 0;

    if (created)
        *created = 0;
    if (!succeeded)
        return 0;
    file_descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (file_descriptor < 0)
        return 0;
    if (created)
        *created = 1;
    for (offset = 0; succeeded && offset < size; offset += sizeof(zeros)) {
        int count = size - offset;
        if (count > (int)sizeof(zeros))
            count = sizeof(zeros);
        succeeded = write_full(file_descriptor, zeros, count);
    }
    if (close(file_descriptor) < 0)
        succeeded = 0;
    if (!succeeded || !file_has_size(path, size))
        return 0;
    for (offset = 0; offset < size; offset += sizeof(zeros)) {
        int count = size - offset;
        if (count > (int)sizeof(zeros))
            count = sizeof(zeros);
        if (!read_file_range(path, offset, verify_buffer, count) ||
            memcmp(verify_buffer, zeros, count) != 0)
            return 0;
    }
    return 1;
}

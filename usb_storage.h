#ifndef USB_STORAGE_H
#define USB_STORAGE_H

int init_usb_storage(const char *directory);

int read_full(int file_descriptor, void *data, int size);
int write_full(int file_descriptor, const void *data, int size);

int file_exists(const char *path);
int file_has_size(const char *path, int size);
int read_exact_file(const char *path, void *data, int size);
int read_text_file(const char *path, char *text, int capacity);
int read_file_range(const char *path, int offset, void *data, int size);
int write_file_range(const char *path, int offset,
                     const void *data, int size);
int write_verified_range(const char *path, int offset,
                         const void *data, int size);
int write_verified_file(const char *path, const void *data, int size);
int replace_verified_file(const char *path, const void *data, int size);
int write_new_verified_file(const char *path, const void *data, int size);
int write_new_verified_file_tracked(const char *path, const void *data,
                                    int size, int *created);
int write_new_zero_file(const char *path, int size);
int write_new_zero_file_tracked(const char *path, int size, int *created);

#endif

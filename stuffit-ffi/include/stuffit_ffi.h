#ifndef STUFFIT_FFI_H
#define STUFFIT_FFI_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STUFFIT_FFI_ABI_VERSION 1
#define STUFFIT_FORK_DATA 0
#define STUFFIT_FORK_RESOURCE 1

typedef struct StuffitArchive StuffitArchive;
typedef struct StuffitWriter StuffitWriter;

typedef enum StuffitErrorCode {
    STUFFIT_OK = 0,
    STUFFIT_ERROR_INVALID_ARGUMENT = 1,
    STUFFIT_ERROR_IO = 2,
    STUFFIT_ERROR_ARCHIVE = 3,
    STUFFIT_ERROR_UNSUPPORTED = 4,
    STUFFIT_ERROR_ENCRYPTED = 5,
    STUFFIT_ERROR_PANIC = 6
} StuffitErrorCode;

typedef struct StuffitBytes {
    const uint8_t *ptr;
    size_t len;
} StuffitBytes;

typedef struct StuffitOwnedBytes {
    uint8_t *ptr;
    size_t len;
} StuffitOwnedBytes;

typedef struct StuffitEntryInfo {
    const char *name;
    size_t data_len;
    size_t resource_len;
    uint8_t file_type[4];
    uint8_t creator[4];
    uint16_t finder_flags;
    uint8_t is_folder;
    uint8_t data_method;
    uint8_t resource_method;
} StuffitEntryInfo;

typedef struct StuffitNewEntry {
    const char *name;
    StuffitBytes data_fork;
    StuffitBytes resource_fork;
    uint8_t file_type[4];
    uint8_t creator[4];
    uint16_t finder_flags;
    uint8_t is_folder;
} StuffitNewEntry;

uint32_t stuffit_ffi_abi_version(void);

StuffitArchive *stuffit_archive_parse_file(const char *path);
StuffitArchive *stuffit_archive_parse_bytes(const uint8_t *data, size_t len);
/* Frees an archive and invalidates all names and fork buffers borrowed from it. */
void stuffit_archive_free(StuffitArchive *archive);

size_t stuffit_archive_entry_count(const StuffitArchive *archive);
int stuffit_archive_entry_info(const StuffitArchive *archive, size_t index,
                               StuffitEntryInfo *out);
int stuffit_archive_entry_fork(const StuffitArchive *archive, size_t index,
                               int fork, StuffitBytes *out);

StuffitWriter *stuffit_writer_new(void);
void stuffit_writer_free(StuffitWriter *writer);
int stuffit_writer_add_entry(StuffitWriter *writer,
                             const StuffitNewEntry *entry);
int stuffit_writer_finish(const StuffitWriter *writer, uint8_t method,
                          StuffitOwnedBytes *out);
/* Each successful writer_finish result must be freed exactly once. */
void stuffit_owned_bytes_free(StuffitOwnedBytes bytes);

/* The code and message describe the last call on the current thread. */
StuffitErrorCode stuffit_last_error_code(void);
const char *stuffit_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* STUFFIT_FFI_H */

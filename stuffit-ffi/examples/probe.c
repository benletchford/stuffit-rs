#include <stdio.h>
#include <stdlib.h>

#include "stuffit_ffi.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s archive.sit\n", argv[0]);
        return EXIT_FAILURE;
    }

    StuffitArchive *archive = stuffit_archive_parse_file(argv[1]);
    if (archive == NULL) {
        fprintf(stderr, "parse failed (%d): %s\n",
                (int)stuffit_last_error_code(), stuffit_last_error());
        return EXIT_FAILURE;
    }

    size_t count = stuffit_archive_entry_count(archive);
    printf("entries: %zu\n", count);
    for (size_t i = 0; i < count; i++) {
        StuffitEntryInfo info;
        if (stuffit_archive_entry_info(archive, i, &info) != 0) {
            fprintf(stderr, "entry failed: %s\n", stuffit_last_error());
            stuffit_archive_free(archive);
            return EXIT_FAILURE;
        }
        printf("%c %s data=%zu resource=%zu\n",
               info.is_folder ? 'd' : 'f', info.name,
               info.data_len, info.resource_len);
    }

    stuffit_archive_free(archive);
    return EXIT_SUCCESS;
}

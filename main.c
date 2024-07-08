#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <byteswap.h>
#include <sys/mman.h>
#include <limits.h>
#include "ext_internal.h"

#define ASDF_MAGIC_TOKEN "#ASDF "
#define ASDF_MAGIC_BLOCK_DATA_TOKEN "\323BLK"
#define ASDF_MAGIC_BLOCK_INDEX_TOKEN "#ASDF BLOCK INDEX\n"
#define ASDF_START_OF_DOCUMENT_TOKEN "---\n"
#define ASDF_END_OF_DOCUMENT_TOKEN "...\n"

enum {
    ASDF_E_SUCCESS=0,
    ASDF_E_READ,
    ASDF_E_WRITE,
    ASDF_E_INVALID,
    ASDF_E_MEMORY,
    ASDF_E_UNKNOWN,
};

enum {
    ASDF_FAILED=-1,
    ASDF_SUCCESS=0,
    ASDF_STREAM,
};

struct ASDFVersion {
    unsigned major;
    unsigned minor;
    unsigned patch;
    char *suffix;
    char *raw;
};

struct ASDFBlock {
    int mfd;            // memmap file descriptor
    const char *mem_region;   // Mapped region (for munmap)
    char *mem;          // Mapped address of size ASDFBlockHeader.used_size
    off_t offset;       // Data offset
    size_t size;        // future
    size_t nelem;       // future
};

struct ASDFBlockHeader {
    unsigned short size;
    unsigned int flags;
    unsigned long allocated_size;
    unsigned long used_size;
    unsigned long data_size;
    char magic_token[4];
    char compression[4];
    char checksum[16];
    struct ASDFBlock data;
};

struct ASDFHandle {
    FILE *fp;                      // File handle
    const char *fp_origin;         // Path to file
    unsigned last_error;           // Last ASDF error recorded (default: ASDF_E_SUCCESS)
    off_t pos;                     // Current position in file
    off_t block_index_offset;      // Block header position in file
    size_t *block_offsets;         // Array of block offsets in file
    unsigned block_stream;         // Streaming detected in file
    struct ASDFVersion version;    // ASDF file version
};

size_t *asdfapi_get_block_index_array(struct ASDFHandle *handle) {
    off_t pos_prev = ftell(handle->fp);
    size_t size_default = 1024;
    size_t *block_list_temp = calloc(size_default, sizeof(*block_list_temp));
    if (!block_list_temp) {
        handle->last_error = ASDF_E_MEMORY;
        return NULL;
    }

    fseek(handle->fp, handle->block_index_offset, SEEK_SET);
    if (handle->block_stream) {
        block_list_temp[0] = handle->block_index_offset;
        fseek(handle->fp, pos_prev, SEEK_SET);
        return block_list_temp;
    }

    char buf[100] = {0};
    size_t i = 0;
    while (fgets(buf, sizeof(buf) - 1, handle->fp) != NULL) {
        if (!strncmp(buf, "%YAML", 5) || !strncmp(buf, ASDF_START_OF_DOCUMENT_TOKEN, strlen(ASDF_START_OF_DOCUMENT_TOKEN))) {
            continue;
        } else if (!strncmp(buf, ASDF_END_OF_DOCUMENT_TOKEN, strlen(ASDF_END_OF_DOCUMENT_TOKEN))) {
            break;
        }
        char *data = strstr(buf, "- ");
        if (data) {
            data += 2;
            block_list_temp[i] = strtoul(data, NULL, 10);
            i++;
        }
    }

    fseek(handle->fp, pos_prev, SEEK_SET);
    return block_list_temp;
}

size_t asdfapi_poll_block_index_offset(struct ASDFHandle *handle) {
    fseek(handle->fp, 0, SEEK_END);
    off_t cur = ftell(handle->fp);
    const size_t magic_size = strlen(ASDF_MAGIC_BLOCK_INDEX_TOKEN);
    char *buf = calloc(magic_size + 1, sizeof(*buf));

    fseek(handle->fp, (ssize_t) -strlen(ASDF_END_OF_DOCUMENT_TOKEN), SEEK_CUR);
    fread(buf, sizeof(*buf), strlen(ASDF_END_OF_DOCUMENT_TOKEN), handle->fp);
    if (strncmp(buf, ASDF_END_OF_DOCUMENT_TOKEN, strlen(ASDF_END_OF_DOCUMENT_TOKEN)) != 0) {
        fprintf(stderr, "STREAM DETECTED\n");
        handle->block_stream = 1;
        cur = ftell(handle->fp);
        while (cur != 0) {
            if (fread(buf, sizeof(*buf), 4, handle->fp) != 4 && ferror(handle->fp)) {
                fprintf(stderr, "read failure\n");
                return -1;
            } else {
                if (!memcmp(buf, ASDF_MAGIC_BLOCK_DATA_TOKEN, 4)) {
                    fseek(handle->fp, -4, SEEK_CUR);
                    cur = ftell(handle->fp);
                    free(buf);
                    return cur;
                }
            }
            fseek(handle->fp, cur, SEEK_SET);
            cur--;
        }
    }

    while (cur != 0) {
        if (fread(buf, sizeof(*buf), magic_size, handle->fp) != magic_size && ferror(handle->fp)) {
            fprintf(stderr, "read failure\n");
            return -1;
        }
        if (!strncmp(buf, ASDF_MAGIC_BLOCK_INDEX_TOKEN, magic_size)) {
            cur = ftell(handle->fp);
            break;
        }
        fseek(handle->fp, cur, SEEK_SET);
        cur--;
    }
    fseek(handle->fp, handle->pos, SEEK_SET);
    handle->pos = ftell(handle->fp);
    free(buf);
    return cur;
}

int asdfapi_poll_version(struct ASDFHandle *handle) {
    char buf[100] = {0};
    if (fgets(buf, sizeof(buf) - 1, handle->fp)) {
        handle->pos = ftell(handle->fp);
        if (!strncmp(buf, ASDF_MAGIC_TOKEN, strlen(ASDF_MAGIC_TOKEN))) {
            char *version_p = strstr(buf, ASDF_MAGIC_TOKEN);
            if (version_p) {
                version_p += strlen(ASDF_MAGIC_TOKEN);
                handle->version.raw = strndup(version_p, strlen(version_p) - 1);
                char *errptr = NULL;
                handle->version.major = strtoul(handle->version.raw, &errptr, 10);
                if (errptr) {
                    handle->version.minor = strtoul(errptr + 1, &errptr, 10);
                }
                if (errptr) {
                    handle->version.patch = strtoul(errptr + 1, &errptr, 10);
                }
                if (errptr && strlen(errptr) && *errptr != '.') {
                    handle->version.suffix = strdup(errptr);
                }
            }
        } else {
            handle->last_error = ASDF_E_INVALID;
            return 1;
        }
    }
    return 0;
}

void asdfapi_close(struct ASDFHandle **handle) {
    if ((*handle)->version.raw) {
        free((char *) (*handle)->version.raw);
        if ((*handle)->version.suffix) {
            free((*handle)->version.suffix);
        }
    }
    if ((*handle)->block_offsets) {
        free((*handle)->block_offsets);
    }
    if ((*handle)->fp) {
        fclose((*handle)->fp);
    }
    free((*handle));
}


struct ASDFHandle *asdfapi_open(struct ASDFHandle **handle, const char *filename) {
    *handle = calloc(1, sizeof(**handle));
    if (!*handle) {
        return NULL;
    }

    (*handle)->fp = fopen(filename, "rb+");
    if (!(*handle)->fp) {
        return NULL;
    }

    (*handle)->fp_origin = filename;
    if (asdfapi_poll_version(*handle)) {
        fprintf(stderr, "failed to determine ASDF file version\n");
        return NULL;
    }

    (*handle)->block_index_offset = (off_t) asdfapi_poll_block_index_offset(*handle);
    (*handle)->block_offsets = asdfapi_get_block_index_array(*handle);
    if (!(*handle)->block_offsets) {
        perror("wtf?");
        return NULL;
    }
    for (size_t i = 0; (*handle)->block_offsets[i] != 0; i++) {
        printf("block[%zu] @ %zu\n", i, (*handle)->block_offsets[i]);
    }
    return *handle;
}

void asdfapi_free_block_header(struct ASDFBlockHeader **hdr) {
    if ((*hdr)->data.mem_region) {
        munmap((char *) (*hdr)->data.mem_region, (*hdr)->used_size);
        (*hdr)->data.mem_region = NULL;
        (*hdr)->data.mem = NULL;
    }
    memset((*hdr), 0, sizeof(*(*hdr)));
    free((*hdr));
}

struct ASDFBlockHeader *asdfapi_read_block_header(struct ASDFHandle *handle, size_t block) {
    struct ASDFBlockHeader *result = calloc(1, sizeof(*result));
    fseek(handle->fp, (off_t) handle->block_offsets[block], SEEK_SET);
    fread(result->magic_token, sizeof(result->magic_token), sizeof(*result->magic_token), handle->fp);
    fread(&result->size, sizeof(result->size), 1, handle->fp);
    result->size = bswap_16(result->size);
    fread(&result->flags, sizeof(result->flags), 1, handle->fp);
    result->flags = bswap_32(result->flags);
    fread(result->compression, sizeof(result->compression), sizeof(*result->compression), handle->fp);
    fread(&result->allocated_size, sizeof(result->allocated_size), 1, handle->fp);
    result->allocated_size = bswap_64(result->allocated_size);
    fread(&result->used_size, sizeof(result->used_size), 1, handle->fp);
    result->used_size = bswap_64(result->used_size);
    fread(&result->data_size, sizeof(result->data_size), 1, handle->fp);
    result->data_size = bswap_64(result->data_size);
    fread(result->checksum, sizeof(result->checksum), 1, handle->fp);
    result->data.offset = ftell(handle->fp);
    result->data.mfd = fileno(handle->fp);
    off_t pa_offset = result->data.offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
    size_t map_size = result->used_size;
    if (result->flags & ASDF_STREAM) {
        map_size = result->size;
    }
    result->data.mem_region = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, result->data.mfd, pa_offset);
    if (result->data.mem_region == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    result->data.mem = (char *) &result->data.mem_region[result->data.offset];

    return result;
}

void asdfapi_show_block_header(struct ASDFBlockHeader *hdr) {
    printf("ASDF HEADER BLOCK\n");
    printf("Raw size: %u\n", hdr->size);
    printf("Allocated size: %zu\n", hdr->allocated_size);
    printf("Used size: %zu\n", hdr->used_size);
    printf("Data size: %zu\n", hdr->data_size);
    printf("Data checksum: ");
    // Quick check: first, middle, and last byte of the MD5 hash are non-zero
    if (hdr->checksum[0] && hdr->checksum[7] && hdr->checksum[15]) {
        // read checksum
        for (size_t i = 0; i < sizeof(hdr->checksum); i++) {
            unsigned char b = (unsigned char) hdr->checksum[i];
            printf("%02X", b);
        }
    } else {
        printf("None");
    }
    printf("\n");

    printf("Compressed: ");
    if (*hdr->compression) {
        char compression[sizeof(hdr->compression) + 1] = {0};
        memcpy(compression, hdr->compression, sizeof(hdr->compression));
        printf("Yes (%s)", compression);
    } else {
        printf("No");
    }
    printf("\n");

    printf("Flags: ");
    if (hdr->flags) {
        unsigned tmp = hdr->flags;
        for (size_t i = 0; i < sizeof(hdr->flags) * 8; i++) {
            unsigned have_flag = tmp & 1;
            if (have_flag) {
                switch (i) {
                    case 0:
                        printf("STREAM ");
                        break;
                    default:
                        printf("UNKNOWN(bit %zu) ", i + 1);
                        break;
                }
            }
            tmp = tmp >> 1;
        }
    } else {
        printf("None");
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    const char *filename = "../ascii.asdf";
    printf("Opening %s\n", filename);
    struct ASDFHandle *handle = NULL;
    asdfapi_open(&handle, filename);
    if (!handle) {
        perror(filename);
        exit(1);
    }

    printf("ASDF file version: %s\n", handle->version.raw);

    if (handle->block_offsets) {
        for (size_t i = 0; handle->block_offsets[i] != 0; i++) {
            struct ASDFBlockHeader *block_hdr = asdfapi_read_block_header(handle, i);
            asdfapi_show_block_header(block_hdr);
            puts("");
            for (size_t b = 0; b < block_hdr->used_size / sizeof(char); b++) {
                printf("%c ", (char) block_hdr->data.mem[b]);
            }
            puts("\n");
            asdfapi_free_block_header(&block_hdr);
        }
    }
    asdfapi_close(&handle);

    // Extension framework test
    const char *libfilename = "extensions/libasdfapi_ext_hello.so";
    struct ASDFExtension *ext_info;

    void *ext = asdfapi_ext_load(&ext_info, libfilename);
    asdfapi_ext_show_descriptor(ext_info);

    typedef int (*fn_sig_say_hello)(const char *);
    fn_sig_say_hello say_hello = asdfapi_ext_call(ext, "say_hello");
    if (say_hello) {
        say_hello("BEEP BEEP");
    } else {
        fprintf(stderr, "%s", dlerror());
        exit(1);
    }
    dlclose(ext);
}

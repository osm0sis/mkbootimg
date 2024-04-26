/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

#include "mincrypt/sha.h"
#include "mincrypt/sha256.h"
#include "bootimg.h"

static void *load_file(const char *fn, unsigned *_sz)
{
    int fd = open(fn, O_RDONLY);
    if(fd < 0) return 0;

    int sz = lseek(fd, 0, SEEK_END);
    if(sz < 0) goto oops;
    if(lseek(fd, 0, SEEK_SET) != 0) goto oops;

    char *data = 0;
    data = (char *)malloc(sz);
    if(data == 0) goto oops;

    if(read(fd, data, sz) != sz) goto oops;
    close(fd);

    if(_sz) *_sz = sz;
    return data;

oops:
    close(fd);
    if(data != 0) free(data);
    return 0;
}

static unsigned char padding[131072] = { 0, };

/*
 * In order to ensure that all allocated memory is deallocated, this
 * array will hold the addresses returned by malloc(), with addr_count
 * holding the addresses as an index
 */
void *addresses[10];
int addr_count = 0;

#define ADD_ADDR(addr)                \
    if(addr != NULL) {                \
        addresses[addr_count] = addr; \
        addr_count += 1;              \
    }

int write_padding(int fd, unsigned pagesize, unsigned itemsize)
{
    unsigned pagemask = pagesize - 1;
    ssize_t count;

    if((itemsize & pagemask) == 0) return 0;

    count = pagesize - (itemsize & pagemask);

    if(write(fd, padding, count) != count) return -1;
    return 0;
}

int parse_os_version(char *ver)
{
    int a = 0, b = 0, c = 0;
    int i = sscanf(ver, "%u.%u.%u", &a, &b, &c);

    if((i >= 1) && (a < 128) && (b < 128) && (c < 128)) {
        return (a << 14) | (b << 7) | c;
    }
    return 0;
}

int parse_os_patch_level(char *lvl)
{
    int y = 0, m = 0;
    int i = sscanf(lvl, "%u-%u", &y, &m);
    y -= 2000;

    if((i == 2) && (y >= 0) && (y < 128) && (m > 0) && (m <= 12)) {
        return (y << 4) | m;
    }
    return 0;
}

/*
 * Reads every file created by unpackbootimg and extracts
 * its values.
 *
 * Parameters:
 * @preffix: the part of the name preceding the value
 * (ex.: boot.img-).
 * @value: this is the name of the parameter itself
 * (ex.: kernel, ramdisk_offset, etc.).
 */
char* read_value_from_file(char *preffix, char *value)
{
    size_t preffix_len   = strlen(preffix);
    size_t value_len     = strlen(value);
    size_t file_name_len = preffix_len + value_len + 1;
    size_t file_size     = 0;
    char *file_name      = malloc(file_name_len);
    char *data           = NULL;
    int fd               = 0;
    int second_fd        = 0;

    memset(file_name, 0, file_name_len);
    memcpy(file_name, preffix, preffix_len);
    memcpy(file_name + preffix_len, "-", 1);
    memcpy(file_name + preffix_len + 1, value, value_len);

    if(!strcmp(value, "second")
       || !strcmp(value, "kernel")
       || !strcmp(value, "ramdisk")) {
        second_fd = open(file_name, O_RDONLY);
        if(second_fd < 0) {
            close(second_fd);
            free(file_name);
            return NULL;
        } else {
            close(second_fd);
            return file_name;
        }
    }

    fd = open(file_name, O_RDONLY);
    if(fd < 0) {
        free(file_name);
        return NULL;
    }

    file_size = lseek(fd, 0, SEEK_END);
    if(file_size == -1) {
        fprintf(stderr, "error: error while reading %s\n", file_name);
        free(file_name);
        return NULL;
    }

    if(lseek(fd, 0, SEEK_SET) == -1) {
        fprintf(stderr, "error: error while reading %s\n", file_name);
        free(file_name);
        return NULL;
    }

    data = malloc(file_size);
    memset(data, 0, file_size);

    if(pread(fd, data, file_size - 1, 0) == -1) {
        fprintf(stderr, "error: error while reading file %s\n", file_name);
        free(file_name);
        free(data);
        return NULL;
    }
    close(fd);
    free(file_name);
    return data;
}

enum hash_alg {
    HASH_UNKNOWN = -1,
    HASH_SHA1 = 0,
    HASH_SHA256,
};

struct hash_name {
    const char *name;
    enum hash_alg alg;
};

const struct hash_name hash_names[] = {
    { "sha1", HASH_SHA1 },
    { "sha256", HASH_SHA256 },
    { NULL, /* Sentinel */ },
};

enum hash_alg parse_hash_alg(char *name)
{
    const struct hash_name *ptr = hash_names;

    while(ptr->name) {
        if(!strcmp(ptr->name, name)) {
            return ptr->alg;
        }
        ptr++;
    }
    return HASH_UNKNOWN;
}

void generate_id_sha1(boot_img_hdr_v2 *hdr, void *kernel_data, void *ramdisk_data,
                      void *second_data, void *dt_data, void *recovery_dtbo_data, void *dtb_data)
{
    SHA_CTX ctx;
    const uint8_t *sha;

    SHA_init(&ctx);
    SHA_update(&ctx, kernel_data, hdr->kernel_size);
    SHA_update(&ctx, &hdr->kernel_size, sizeof(hdr->kernel_size));
    SHA_update(&ctx, ramdisk_data, hdr->ramdisk_size);
    SHA_update(&ctx, &hdr->ramdisk_size, sizeof(hdr->ramdisk_size));
    SHA_update(&ctx, second_data, hdr->second_size);
    SHA_update(&ctx, &hdr->second_size, sizeof(hdr->second_size));
    if(dt_data) {
        SHA_update(&ctx, dt_data, hdr->dt_size);
        SHA_update(&ctx, &hdr->dt_size, sizeof(hdr->dt_size));
    } else if(hdr->header_version > 0) {
        SHA_update(&ctx, recovery_dtbo_data, hdr->recovery_dtbo_size);
        SHA_update(&ctx, &hdr->recovery_dtbo_size, sizeof(hdr->recovery_dtbo_size));
        if(hdr->header_version > 1) {
            SHA_update(&ctx, dtb_data, hdr->dtb_size);
            SHA_update(&ctx, &hdr->dtb_size, sizeof(hdr->dtb_size));
        }
    }
    sha = SHA_final(&ctx);
    memcpy(hdr->id, sha, SHA_DIGEST_SIZE > sizeof(hdr->id) ? sizeof(hdr->id) : SHA_DIGEST_SIZE);
}

void generate_id_sha256(boot_img_hdr_v2 *hdr, void *kernel_data, void *ramdisk_data,
                        void *second_data, void *dt_data, void *recovery_dtbo_data, void *dtb_data)
{
    SHA256_CTX ctx;
    const uint8_t *sha;

    SHA256_init(&ctx);
    SHA256_update(&ctx, kernel_data, hdr->kernel_size);
    SHA256_update(&ctx, &hdr->kernel_size, sizeof(hdr->kernel_size));
    SHA256_update(&ctx, ramdisk_data, hdr->ramdisk_size);
    SHA256_update(&ctx, &hdr->ramdisk_size, sizeof(hdr->ramdisk_size));
    SHA256_update(&ctx, second_data, hdr->second_size);
    SHA256_update(&ctx, &hdr->second_size, sizeof(hdr->second_size));
    if(dt_data) {
        SHA256_update(&ctx, dt_data, hdr->dt_size);
        SHA256_update(&ctx, &hdr->dt_size, sizeof(hdr->dt_size));
    } else if(hdr->header_version > 0) {
        SHA256_update(&ctx, recovery_dtbo_data, hdr->recovery_dtbo_size);
        SHA256_update(&ctx, &hdr->recovery_dtbo_size, sizeof(hdr->recovery_dtbo_size));
        if(hdr->header_version > 1) {
            SHA256_update(&ctx, dtb_data, hdr->dtb_size);
            SHA256_update(&ctx, &hdr->dtb_size, sizeof(hdr->dtb_size));
        }
    }
    sha = SHA256_final(&ctx);
    memcpy(hdr->id, sha, SHA256_DIGEST_SIZE > sizeof(hdr->id) ? sizeof(hdr->id) : SHA256_DIGEST_SIZE);
}

void generate_id(enum hash_alg alg, boot_img_hdr_v2 *hdr, void *kernel_data,
                 void *ramdisk_data, void *second_data, void *dt_data, void *recovery_dtbo_data, void *dtb_data)
{
    switch(alg) {
        case HASH_SHA1:
            generate_id_sha1(hdr, kernel_data, ramdisk_data, second_data, dt_data, recovery_dtbo_data, dtb_data);
            break;
        case HASH_SHA256:
            generate_id_sha256(hdr, kernel_data, ramdisk_data, second_data, dt_data, recovery_dtbo_data, dtb_data);
            break;
        case HASH_UNKNOWN:
        default:
            fprintf(stderr, "Unknown hash type.\n");
    }
}

static void print_id(const uint8_t *id, size_t id_len)
{
    printf("0x");
    unsigned i = 0;
    for(i = 0; i < id_len; i++) {
        printf("%02x", id[i]);
    }
    printf("\n");
}

int usage(void)
{
    fprintf(stderr,
        "usage: mkbootimg\n"
        "\t[ --from-unpackbootimg-files <preffix> ]\n"
        "\t[ --kernel <filename> ]\n"
        "\t[ --ramdisk <filename> | --vendor_ramdisk <filename> ]\n"
        "\t[ --second <filename> ]\n"
        "\t[ --dtb <filename> ]\n"
        "\t[ --recovery_dtbo <filename> | --recovery_acpio <filename> ]\n"
        "\t[ --dt <filename> ]\n"
        "\t[ --cmdline <command line> | --vendor_cmdline <command line> ]\n"
        "\t[ --base <address> ]\n"
        "\t[ --kernel_offset <base offset> ]\n"
        "\t[ --ramdisk_offset <base offset> ]\n"
        "\t[ --second_offset <base offset> ]\n"
        "\t[ --tags_offset <base offset> ]\n"
        "\t[ --dtb_offset <base offset> ]\n"
        "\t[ --os_version <A.B.C version> ]\n"
        "\t[ --os_patch_level <YYYY-MM-DD date> ]\n"
        "\t[ --board <board name> ]\n"
        "\t[ --pagesize <pagesize> ]\n"
        "\t[ --header_version <version number> ]\n"
        "\t[ --hashtype <sha1(default)|sha256> ]\n"
        "\t[ --id ]\n"
        "\t-o|--output <filename> | --vendor_boot <filename>\n"
    );
    return 1;
}

int main(int argc, char **argv)
{
    char *bootimg = NULL;
    char *kernel_fn = NULL;
    char *files_preffix = NULL;
    char *hash_alg_val = "sha1";
    char *temp_pagesize = NULL;
    char *temp_base = NULL;
    char *temp_kernel_offset = NULL;
    char *temp_ramdisk_offset = NULL;
    char *temp_header_version = NULL;
    char *temp_os_patch_level = NULL;
    char *temp_os_version = NULL;
    char *temp_second_offset = NULL;
    char *temp_tags_offset = NULL;
    char *temp_board = NULL;
    char *temp_cmdline = NULL;
    char *temp_hash_alg_val = NULL;
    void *kernel_data = NULL;
    char *ramdisk_fn = NULL;
    void *ramdisk_data = NULL;
    char *second_fn = NULL;
    void *second_data = NULL;
    char *dtb_fn = NULL;
    void *dtb_data = NULL;
    char *recovery_dtbo_fn = NULL;
    void *recovery_dtbo_data = NULL;
    char *dt_fn = NULL;
    void *dt_data = NULL;
    char *cmdline = "";
    char *board = "";
    int os_version = 0;
    int os_patch_level = 0;
    int header_version = 0;
    int orig_argc = argc;
    uint32_t pagesize        = 2048;
    uint32_t base            = 0x10000000U;
    uint32_t kernel_offset   = 0x00008000U;
    uint32_t ramdisk_offset  = 0x01000000U;
    uint32_t second_offset   = 0x00f00000U;
    uint32_t tags_offset     = 0x00000100U;
    uint64_t dtb_offset      = 0x01f00000U;
    uint64_t rec_dtbo_offset = 0;
    uint32_t kernel_sz       = 0;
    uint32_t ramdisk_sz      = 0;
    uint32_t second_sz       = 0;
    uint32_t dtb_sz          = 0;
    uint32_t rec_dtbo_sz     = 0;
    uint32_t dt_sz           = 0;
    uint32_t header_sz       = 0;

    size_t cmdlen;
    enum hash_alg hash_alg = HASH_SHA1;

    bool show_id = false;
    bool vendor_boot = false;

    argc--;
    argv++;
    while(argc > 0) {
        char *arg = argv[0];
        if(!strcmp(arg, "--id")) {
            show_id = true;
            argc -= 1;
            argv += 1;
            continue;
        }
        if(!strcmp(arg, "--from-unpackbootimg-files")) {
            if((orig_argc - 1) != argc) {
                fprintf(stderr, "error: --from-unmkbootimg-files must be the first parameter\n");
                return usage();
            }
            if(argc > 1 && (argv + 1)[0][0] != '-') {
                argc -= 1;
                argv += 1;

                files_preffix = argv[0];

                kernel_fn = read_value_from_file(files_preffix, "kernel");
                ADD_ADDR(kernel_fn);

                ramdisk_fn = read_value_from_file(files_preffix, "ramdisk");
                ADD_ADDR(ramdisk_fn);

                second_fn = read_value_from_file(files_preffix, "second");
                ADD_ADDR(second_fn);

                /* pagesize */
                temp_pagesize = read_value_from_file(files_preffix, "pagesize");
                pagesize = temp_pagesize == NULL ? pagesize : strtoul(temp_pagesize, 0, 10);
                free(temp_pagesize);

                temp_cmdline = read_value_from_file(files_preffix, "cmdline");
                cmdline = temp_cmdline == NULL ? "" : temp_cmdline;
                ADD_ADDR(temp_cmdline);

                /* base */
                temp_base = read_value_from_file(files_preffix, "base");
                base = temp_base == NULL ? base : strtoul(temp_base, 0, 16);
                free(temp_base);

                temp_board = read_value_from_file(files_preffix, "board");
                board = temp_board == NULL ? "" : temp_board;
                ADD_ADDR(temp_board);

                /* kernel_offset */
                temp_kernel_offset = read_value_from_file(files_preffix, "kernel_offset");
                kernel_offset = temp_kernel_offset == NULL ? kernel_offset : strtoul(temp_kernel_offset, 0, 16);
                free(temp_kernel_offset);

                /* ramdisk_offset */
                temp_ramdisk_offset = read_value_from_file(files_preffix, "ramdisk_offset");
                ramdisk_offset = temp_ramdisk_offset == NULL ? ramdisk_offset : strtoul(temp_ramdisk_offset, 0, 16);
                free(temp_ramdisk_offset);

                /* hashtype */
                temp_hash_alg_val = read_value_from_file(files_preffix, "hashtype");
                hash_alg_val = temp_hash_alg_val == NULL ? "sha1" : temp_hash_alg_val;
                ADD_ADDR(temp_hash_alg_val);

                /* header_version */
                temp_header_version = read_value_from_file(files_preffix, "header_version");
                header_version = temp_header_version == NULL ? header_version : strtoul(temp_header_version, 0, 10);
                free(temp_header_version);

                /* os_patch_level */
                temp_os_patch_level = read_value_from_file(files_preffix, "os_patch_level");
                os_patch_level = temp_os_patch_level == NULL ? os_patch_level : parse_os_patch_level(temp_os_patch_level);
                free(temp_os_patch_level);

                /* os_version */
                temp_os_version = read_value_from_file(files_preffix, "os_version");
                os_version = temp_os_version == NULL ? os_version : parse_os_version(temp_os_version);
                free(temp_os_version);

                /* second_offset */
                temp_second_offset = read_value_from_file(files_preffix, "second_offset");
                second_offset = temp_second_offset == NULL ? second_offset : strtoul(temp_second_offset, 0, 16);
                free(temp_second_offset);

                /* tags_offset */
                temp_tags_offset = read_value_from_file(files_preffix, "tags_offset");
                tags_offset = temp_tags_offset == NULL ? tags_offset : strtoul(temp_tags_offset, 0, 16);
                free(temp_tags_offset);

                argc -= 1;
                argv += 1;
                continue;
            } else {
                fprintf(stderr, "error: specify the preffix of the files created by unpackbootimg\n");
                return usage();
            }
        }
        if(argc >= 2) {
            char *val = argv[1];
            argc -= 2;
            argv += 2;
            if(!strcmp(arg, "--output") || !strcmp(arg, "-o")) {
                bootimg = val;
            } else if(!strcmp(arg, "--vendor_boot")) {
                vendor_boot = true;
                bootimg = val;
            } else if(!strcmp(arg, "--kernel") && kernel_fn == NULL) {
                kernel_fn = val;
            } else if(!strcmp(arg, "--ramdisk") && ramdisk_fn == NULL) {
                ramdisk_fn = val;
            } else if(!strcmp(arg, "--vendor_ramdisk")) {
                vendor_boot = true;
                ramdisk_fn = val;
            } else if(!strcmp(arg, "--second") && second_fn == NULL) {
                second_fn = val;
            } else if(!strcmp(arg, "--dtb")) {
                dtb_fn = val;
            } else if(!strcmp(arg, "--recovery_dtbo") || !strcmp(arg, "--recovery_acpio")) {
                recovery_dtbo_fn = val;
            } else if(!strcmp(arg, "--dt")) {
                dt_fn = val;
            } else if(!strcmp(arg, "--cmdline") && temp_cmdline == NULL) {
                cmdline = val;
            } else if(!strcmp(arg, "--vendor_cmdline")) {
                vendor_boot = true;
                cmdline = val;
            } else if(!strcmp(arg, "--base")) {
                base = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--kernel_offset")) {
                kernel_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--ramdisk_offset")) {
                ramdisk_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--second_offset")) {
                second_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--tags_offset")) {
                tags_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--dtb_offset")) {
                dtb_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--os_version")) {
                os_version = parse_os_version(val);
            } else if(!strcmp(arg, "--os_patch_level")) {
                os_patch_level = parse_os_patch_level(val);
            } else if(!strcmp(arg, "--board") && temp_board == NULL) {
                board = val;
            } else if(!strcmp(arg,"--pagesize")) {
                pagesize = strtoul(val, 0, 10);
            } else if(!strcmp(arg, "--header_version")) {
                header_version = strtoul(val, 0, 10);
            } else if(!strcmp(arg, "--hashtype") && temp_hash_alg_val == NULL) {
                hash_alg_val = val;
            } else {
                fprintf(stderr, "error: unknown argument '%s'\n", arg);
                return usage();
            }
        } else {
            fprintf(stderr, "error: not enough arguments '%s'\n", arg);
            return usage();
        }
    }

    if(bootimg == NULL) {
        fprintf(stderr, "error: no output filename specified\n");
        return usage();
    }

    int fd = open(bootimg, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
        fprintf(stderr, "error: could not create '%s'\n", bootimg);
        return 1;
    }

    if(!vendor_boot) {

        if(kernel_fn == 0) {
            fprintf(stderr, "error: no kernel image specified\n");
            return usage();
        }

        if(header_version < 3) {
            // boot_img_hdr_v2 in the backported header supports all boot_img_hdr versions and cross-compatible variants below 3

            boot_img_hdr_v2 hdr;
            memset(&hdr, 0, sizeof(hdr));

            memcpy(hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

            if((pagesize != 2048) && (pagesize != 4096)
                && (pagesize != 8192) && (pagesize != 16384)
                && (pagesize != 32768) && (pagesize != 65536)
                && (pagesize != 131072)) {
                fprintf(stderr, "error: unsupported pagesize %u\n", pagesize);
                close(fd);
                return 1;
            }
            hdr.page_size = pagesize;

            hdr.kernel_addr  = base + kernel_offset;
            hdr.ramdisk_addr = base + ramdisk_offset;
            hdr.second_addr  = base + second_offset;
            hdr.tags_addr    = base + tags_offset;

            hdr.header_version = header_version;
            hdr.os_version = (os_version << 11) | os_patch_level;

            if(strlen(board) >= BOOT_NAME_SIZE) {
                fprintf(stderr, "error: board name too large\n");
                return usage();
            }
            strcpy((char *)hdr.name, board);

            cmdlen = strlen(cmdline);
            if(cmdlen <= BOOT_ARGS_SIZE) {
                strcpy((char *)hdr.cmdline, cmdline);
            } else if(cmdlen <= BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE) {
                // exceeds the limits of the base command-line size, go for the extra
                memcpy(hdr.cmdline, cmdline, BOOT_ARGS_SIZE);
                strcpy((char *)hdr.extra_cmdline, cmdline+BOOT_ARGS_SIZE);
            } else {
                fprintf(stderr, "error: kernel cmdline too large\n");
                return 1;
            }

            kernel_data = load_file(kernel_fn, &kernel_sz);
            if(kernel_data == 0) {
                fprintf(stderr, "error: could not load kernel '%s'\n", kernel_fn);
                return 1;
            }
            hdr.kernel_size = kernel_sz;

            if(ramdisk_fn == NULL) {
                ramdisk_data = 0;
            } else {
                ramdisk_data = load_file(ramdisk_fn, &ramdisk_sz);
                if(ramdisk_data == 0) {
                    fprintf(stderr, "error: could not load ramdisk '%s'\n", ramdisk_fn);
                    return 1;
                }
            }
            hdr.ramdisk_size = ramdisk_sz;

            if(second_fn) {
                second_data = load_file(second_fn, &second_sz);
                if(second_data == 0) {
                    fprintf(stderr, "error: could not load second '%s'\n", second_fn);
                    return 1;
                }
            }
            hdr.second_size = second_sz;

            if(header_version == 0) {
                if(dt_fn) {
                    dt_data = load_file(dt_fn, &dt_sz);
                    if((dt_data == 0) || (dt_sz == 0)) {
                        fprintf(stderr, "error: could not load dt '%s'\n", dt_fn);
                        return 1;
                    }
                }
                hdr.dt_size = dt_sz; // overrides hdr.header_version
            } else {
                if(recovery_dtbo_fn) {
                    recovery_dtbo_data = load_file(recovery_dtbo_fn, &rec_dtbo_sz);
                    if((recovery_dtbo_data == 0) || (rec_dtbo_sz == 0)) {
                        fprintf(stderr, "error: could not load recovery dtbo/acpio '%s'\n", recovery_dtbo_fn);
                        return 1;
                    }
                    // header occupies a page
                    rec_dtbo_offset = pagesize * (1 +
                        (kernel_sz + pagesize - 1) / pagesize +
                        (ramdisk_sz + pagesize - 1) / pagesize +
                        (second_sz + pagesize - 1) / pagesize
                    );
                }
                if(header_version > 1) {
                    if(dtb_fn) {
                        dtb_data = load_file(dtb_fn, &dtb_sz);
                        if((dtb_data == 0) || (dtb_sz == 0)) {
                            fprintf(stderr, "error: could not load dtb '%s'\n", dtb_fn);
                            return 1;
                        }
                    }
                    hdr.dtb_addr = base + dtb_offset;
                }
                if(header_version == 1) {
                    header_sz = 1648;
                } else {
                    header_sz = sizeof(hdr); // this will always show 1660 here since it uses boot_img_hdr_v2
                }
            }
            hdr.recovery_dtbo_size = rec_dtbo_sz;
            hdr.recovery_dtbo_offset = rec_dtbo_offset;
            hdr.header_size = header_sz;
            hdr.dtb_size = dtb_sz;
            if(header_version < 2) {
                hdr.dtb_addr = 0;
            }

            hash_alg = parse_hash_alg(hash_alg_val);
            if(hash_alg == HASH_UNKNOWN) {
                    fprintf(stderr, "error: unknown hash algorithm '%s'\n", hash_alg_val);
                    return -1;
            }
            // put a hash of the contents in the header so boot images can be differentiated based on their first 2k
            generate_id(hash_alg, &hdr, kernel_data, ramdisk_data, second_data, dt_data, recovery_dtbo_data, dtb_data);

            if(write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) goto fail;
            if(write_padding(fd, pagesize, sizeof(hdr))) goto fail;

            if(write(fd, kernel_data, hdr.kernel_size) != (ssize_t) hdr.kernel_size) goto fail;
            if(write_padding(fd, pagesize, hdr.kernel_size)) goto fail;

            if(write(fd, ramdisk_data, hdr.ramdisk_size) != (ssize_t) hdr.ramdisk_size) goto fail;
            if(write_padding(fd, pagesize, hdr.ramdisk_size)) goto fail;

            if(second_data) {
                if(write(fd, second_data, hdr.second_size) != (ssize_t) hdr.second_size) goto fail;
                if(write_padding(fd, pagesize, hdr.second_size)) goto fail;
            }

            if(dt_data) {
                if(write(fd, dt_data, hdr.dt_size) != (ssize_t) hdr.dt_size) goto fail;
                if(write_padding(fd, pagesize, hdr.dt_size)) goto fail;
            } else {
                if(recovery_dtbo_data) {
                    if(write(fd, recovery_dtbo_data, hdr.recovery_dtbo_size) != (ssize_t) hdr.recovery_dtbo_size) goto fail;
                    if(write_padding(fd, pagesize, hdr.recovery_dtbo_size)) goto fail;
                }
                if(dtb_data) {
                    if(write(fd, dtb_data, hdr.dtb_size) != (ssize_t) hdr.dtb_size) goto fail;
                    if(write_padding(fd, pagesize, hdr.dtb_size)) goto fail;
                }
            }

            if(show_id) {
                print_id((uint8_t *)hdr.id, sizeof(hdr.id));
            }

        } else {
            // boot_img_hdr_v3 and above are no longer backwards compatible

            boot_img_hdr_v3 hdr;
            memset(&hdr, 0, sizeof(hdr));

            memcpy(hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

            pagesize = 4096; // page_size is hardcoded to 4096 in boot_img_hdr_v3 and above

            hdr.os_version = (os_version << 11) | os_patch_level;
            hdr.header_size = sizeof(hdr);
            hdr.header_version = header_version;

            cmdlen = strlen(cmdline);
            if(cmdlen <= BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE) {
                strcpy((char *)hdr.cmdline, cmdline);
            } else {
                fprintf(stderr, "error: kernel cmdline too large\n");
                return 1;
            }

            kernel_data = load_file(kernel_fn, &kernel_sz);
            if(kernel_data == 0) {
                fprintf(stderr, "error: could not load kernel '%s'\n", kernel_fn);
                return 1;
            }
            hdr.kernel_size = kernel_sz;

            if(ramdisk_fn == NULL) {
                ramdisk_data = 0;
            } else {
                ramdisk_data = load_file(ramdisk_fn, &ramdisk_sz);
                if(ramdisk_data == 0) {
                    fprintf(stderr, "error: could not load ramdisk '%s'\n", ramdisk_fn);
                    return 1;
                }
            }
            hdr.ramdisk_size = ramdisk_sz;

            if(write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) goto fail;
            if(write_padding(fd, pagesize, sizeof(hdr))) goto fail;

            if(write(fd, kernel_data, hdr.kernel_size) != (ssize_t) hdr.kernel_size) goto fail;
            if(write_padding(fd, pagesize, hdr.kernel_size)) goto fail;

            if(write(fd, ramdisk_data, hdr.ramdisk_size) != (ssize_t) hdr.ramdisk_size) goto fail;
            if(write_padding(fd, pagesize, hdr.ramdisk_size)) goto fail;

        }
    } else {
        // vendor_boot_img_hdr started at v3 and is not cross-compatible with boot_img_hdr

        vendor_boot_img_hdr_v3 hdr;
        memset(&hdr, 0, sizeof(hdr));

        memcpy(hdr.magic, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE);

        if(header_version < 3) {
            header_version = 3;
        }
        hdr.header_version = header_version;
        hdr.page_size = pagesize;

        hdr.kernel_addr  = base + kernel_offset;
        hdr.ramdisk_addr = base + ramdisk_offset;
        hdr.tags_addr    = base + tags_offset;
        hdr.dtb_addr     = base + dtb_offset;

        hdr.header_size = sizeof(hdr);

        if(strlen(board) >= VENDOR_BOOT_NAME_SIZE) {
            fprintf(stderr, "error: board name too large\n");
            return usage();
        }
        strcpy((char *)hdr.name, board);

        cmdlen = strlen(cmdline);
        if(cmdlen <= VENDOR_BOOT_ARGS_SIZE) {
            strcpy((char *)hdr.cmdline, cmdline);
        } else {
            fprintf(stderr, "error: vendor cmdline too large\n");
            return 1;
        }

        if(ramdisk_fn == NULL) {
            ramdisk_data = 0;
        } else {
            ramdisk_data = load_file(ramdisk_fn, &ramdisk_sz);
            if((ramdisk_data == 0) || (ramdisk_sz == 0)) {
                fprintf(stderr, "error: could not load vendor ramdisk '%s'\n", ramdisk_fn);
                return 1;
            }
        }
        hdr.vendor_ramdisk_size = ramdisk_sz;

        if(dtb_fn == NULL) {
            dtb_data = 0;
        } else {
            dtb_data = load_file(dtb_fn, &dtb_sz);
            if((dtb_data == 0) || (dtb_sz == 0)) {
                fprintf(stderr, "error: could not load dtb '%s'\n", dtb_fn);
                return 1;
            }
        }
        hdr.dtb_size = dtb_sz;

        if(write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) goto fail;
        if(write_padding(fd, pagesize, sizeof(hdr))) goto fail;

        if(write(fd, ramdisk_data, hdr.vendor_ramdisk_size) != (ssize_t) hdr.vendor_ramdisk_size) goto fail;
        if(write_padding(fd, pagesize, hdr.vendor_ramdisk_size)) goto fail;

        if(write(fd, dtb_data, hdr.dtb_size) != (ssize_t) hdr.dtb_size) goto fail;
        if(write_padding(fd, pagesize, hdr.dtb_size)) goto fail;

    }

    for(int i = 0; i < addr_count; i++) {
        free(addresses[i]);
    }
    return 0;

fail:
    unlink(bootimg);
    close(fd);
    fprintf(stderr, "error: failed writing '%s': %s\n", bootimg, strerror(errno));
    return 1;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "mincrypt/sha.h"
#include "mincrypt/sha256.h"
#include "bootimg.h"

typedef unsigned char byte;

char *directory = "./";
char *filename = NULL;
int debug = 0;

int total_read = 0;

int pagesize = 0;
int a = 0, b = 0, c = 0, y = 0, m = 0; // header.os_version component calculation variables

int read_padding(FILE *f, unsigned itemsize)
{
    byte *buf = (byte *)malloc(sizeof(byte) * pagesize);
    unsigned pagemask = pagesize - 1;
    unsigned count;
    if((itemsize & pagemask) == 0) {
        free(buf);
        return 0;
    }
    count = pagesize - (itemsize & pagemask);
    if(fread(buf, count, 1, f)) {};
    free(buf);
    if(debug > 1) fprintf(stderr, "read padding: %d\n", count);
    return count;
}

void write_string_to_file(const char *name, const char *string)
{
    char file[PATH_MAX];
    sprintf(file, "%s/%s-%s", directory, basename(filename), name);
    FILE *t = fopen(file, "w");
    if(debug > 0) fprintf(stderr, "%s...\n", name);
    fwrite(string, strlen(string), 1, t);
    fwrite("\n", 1, 1, t);
    fclose(t);
}

void write_buffer_to_file(const char *name, FILE *f, const int size)
{
    char file[PATH_MAX];
    sprintf(file, "%s/%s-%s", directory, basename(filename), name);
    FILE *t = fopen(file, "wb");
    byte *buf = (byte *)malloc(size);
    if(debug > 0) fprintf(stderr, "Reading %s...\n", name);
    if(fread(buf, size, 1, f)) {};
    total_read += size;
    if(debug > 1) fprintf(stderr, "read: %d\n", size);
    fwrite(buf, size, 1, t);
    fclose(t);
    free(buf);
    total_read += read_padding(f, size);
}

const char *detect_hash_type(boot_img_hdr_v2 *hdr)
{
    // sha1 is expected to have zeroes in id[20] and higher
    // offset by 4 to accomodate bootimg variants with BOOT_NAME_SIZE 20
    uint8_t id[SHA256_DIGEST_SIZE];
    memcpy(&id, hdr->id, sizeof(id));
    int i;
    for(i = SHA_DIGEST_SIZE + 4; i < SHA256_DIGEST_SIZE; ++i) {
        if(id[i]) {
            return "sha256";
        }
    }
    return "sha1";
}

int print_os_version(uint32_t hdr_os_ver)
{
    if(hdr_os_ver != 0) {
        int os_version = 0, os_patch_level = 0;
        os_version = hdr_os_ver >> 11;
        os_patch_level = hdr_os_ver&0x7ff;

        a = (os_version >> 14)&0x7f;
        b = (os_version >> 7)&0x7f;
        c = os_version&0x7f;

        y = (os_patch_level >> 4) + 2000;
        m = os_patch_level&0xf;
    }
    if((a < 128) && (b < 128) && (c < 128) && (y >= 2000) && (y < 2128) && (m > 0) && (m <= 12)) {
        printf("BOARD_OS_VERSION %d.%d.%d\n", a, b, c);
        printf("BOARD_OS_PATCH_LEVEL %d-%02d\n", y, m);
        return 0;
    }
    return 1;
}

int usage(void)
{
    fprintf(stderr,
        "usage: unpackbootimg\n"
        "\t-i|--input <filename>\n"
        "\t[ -o|--output <directory> ]\n"
        "\t[ -p|--pagesize <size-in-hexadecimal> ]\n"
    );
    if(debug > 0) fprintf(stderr, "\t[ -d|--debug <debug-level> ]\n");
    return 1;
}

int main(int argc, char **argv)
{
    char tmp[BOOT_MAGIC_SIZE];
    char *magic = NULL;
    int base = 0;

    int seeklimit = 65536; // arbitrary byte limit to search in input file for ANDROID!/VNDRBOOT magic
    int hdr_ver_max = 8; // arbitrary maximum header version value; when greater assume the field is appended dt size

    argc--;
    argv++;
    while(argc > 0) {
        char *arg = argv[0];
        char *val = argv[1];
        argc -= 2;
        argv += 2;
        if(!strcmp(arg, "--input") || !strcmp(arg, "-i")) {
            filename = val;
        } else if(!strcmp(arg, "--output") || !strcmp(arg, "-o")) {
            directory = val;
        } else if(!strcmp(arg, "--pagesize") || !strcmp(arg, "-p")) {
            pagesize = strtoul(val, 0, 16);
        } else if(!strcmp(arg, "--debug") || !strcmp(arg, "-d")) {
            debug = strtoul(val, 0, 10);
        } else {
            return usage();
        }
    }

    if(filename == NULL) {
        return usage();
    }

    struct stat st;
    if(stat(directory, &st) == (-1)) {
        fprintf(stderr, "Could not stat %s: %s\n", directory, strerror(errno));
        return 1;
    }
    if(!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "%s is not a directory\n", directory);
        return 1;
    }

    FILE *f = fopen(filename, "rb");
    if(!f) {
        fprintf(stderr, "Could not open input file: %s\n", strerror(errno));
        return 1;
    }

    if(debug > 0) fprintf(stderr, "Reading header...\n");
    int i;
    for(i = 0; i <= seeklimit; i++) {
        fseek(f, i, SEEK_SET);
        if(fread(tmp, BOOT_MAGIC_SIZE, 1, f)) {};
        if(memcmp(tmp, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0) {
            magic = BOOT_MAGIC;
            break;
        }
        if(memcmp(tmp, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE) == 0) {
            magic = VENDOR_BOOT_MAGIC;
            break;
        }
    }
    total_read = i;
    if(i > seeklimit) {
        fprintf(stderr, "Boot image magic not found.\n");
        return 1;
    }
    printf("%s magic found at: %d\n", magic, i);

    boot_img_hdr_v3 header;
    fseek(f, i, SEEK_SET);
    if(fread(&header, sizeof(header), 1, f)) {};

    if(!strcmp(magic, BOOT_MAGIC)) {
        if((header.header_version < 3) || (header.header_version > hdr_ver_max)) {
            // boot_img_hdr_v2 in the backported header supports all boot_img_hdr versions and cross-compatible variants below 3

            fseek(f, i, SEEK_SET);
            boot_img_hdr_v2 header;
            if(fread(&header, sizeof(header), 1, f)) {};

            base = header.kernel_addr - 0x00008000;
            if(pagesize == 0) {
                pagesize = header.page_size;
            }
            const char *hash_type = detect_hash_type(&header);

            printf("BOARD_KERNEL_CMDLINE %.*s%.*s\n", BOOT_ARGS_SIZE, header.cmdline, BOOT_EXTRA_ARGS_SIZE, header.extra_cmdline);
            printf("BOARD_KERNEL_BASE 0x%08x\n", base);
            printf("BOARD_NAME %s\n", header.name);
            printf("BOARD_PAGE_SIZE %d\n", header.page_size);
            printf("BOARD_HASH_TYPE %s\n", hash_type);
            printf("BOARD_KERNEL_OFFSET 0x%08x\n", header.kernel_addr - base);
            printf("BOARD_RAMDISK_OFFSET 0x%08x\n", header.ramdisk_addr - base);
            printf("BOARD_SECOND_OFFSET 0x%08x\n", header.second_addr - base);
            printf("BOARD_TAGS_OFFSET 0x%08x\n", header.tags_addr - base);
            if(print_os_version(header.os_version) == 1) {
                header.os_version = 0;
            }
            if(header.dt_size > hdr_ver_max) {
                printf("BOARD_DT_SIZE %d\n", header.dt_size);
            } else {
                printf("BOARD_HEADER_VERSION %d\n", header.header_version);
            }
            if(header.header_version <= hdr_ver_max) {
                if(header.header_version > 0) {
                    if(header.recovery_dtbo_size != 0) {
                        printf("BOARD_RECOVERY_DTBO_SIZE %d\n", header.recovery_dtbo_size);
                        printf("BOARD_RECOVERY_DTBO_OFFSET %"PRId64"\n", header.recovery_dtbo_offset);
                    }
                    printf("BOARD_HEADER_SIZE %d\n", header.header_size);
                } else {
                    header.recovery_dtbo_size = 0;
                }
                if(header.header_version > 1) {
                    if(header.dtb_size != 0) {
                        printf("BOARD_DTB_SIZE %d\n", header.dtb_size);
                        printf("BOARD_DTB_OFFSET 0x%08"PRIx64"\n", header.dtb_addr - base);
                    }
                } else {
                    header.dtb_size = 0;
                }
            }

            char cmdlinetmp[BOOT_ARGS_SIZE+BOOT_EXTRA_ARGS_SIZE+1];
            sprintf(cmdlinetmp, "%.*s%.*s", BOOT_ARGS_SIZE, header.cmdline, BOOT_EXTRA_ARGS_SIZE, header.extra_cmdline);
            cmdlinetmp[BOOT_ARGS_SIZE+BOOT_EXTRA_ARGS_SIZE]='\0';
            write_string_to_file("cmdline", cmdlinetmp);

            write_string_to_file("board", (char *)header.name);

            char basetmp[200];
            sprintf(basetmp, "0x%08x", base);
            write_string_to_file("base", basetmp);

            char pagesizetmp[200];
            sprintf(pagesizetmp, "%d", header.page_size);
            write_string_to_file("pagesize", pagesizetmp);

            char kernelofftmp[200];
            sprintf(kernelofftmp, "0x%08x", header.kernel_addr - base);
            write_string_to_file("kernel_offset", kernelofftmp);

            char ramdiskofftmp[200];
            sprintf(ramdiskofftmp, "0x%08x", header.ramdisk_addr - base);
            write_string_to_file("ramdisk_offset", ramdiskofftmp);

            char secondofftmp[200];
            sprintf(secondofftmp, "0x%08x", header.second_addr - base);
            write_string_to_file("second_offset", secondofftmp);

            char tagsofftmp[200];
            sprintf(tagsofftmp, "0x%08x", header.tags_addr - base);
            write_string_to_file("tags_offset", tagsofftmp);

            if(header.os_version != 0) {
                char osvertmp[200];
                sprintf(osvertmp, "%d.%d.%d", a, b, c);
                write_string_to_file("os_version", osvertmp);

                char oslvltmp[200];
                sprintf(oslvltmp, "%d-%02d", y, m);
                write_string_to_file("os_patch_level", oslvltmp);
            }

            if(header.header_version <= hdr_ver_max) {
                char hdrvertmp[200];
                sprintf(hdrvertmp, "%d\n", header.header_version); // extra newline to prevent some file editors from interpreting a 2-byte file as Unicode
                write_string_to_file("header_version", hdrvertmp);

                if(header.header_version > 1) {
                    char dtbofftmp[200];
                    sprintf(dtbofftmp, "0x%08"PRIx64, header.dtb_addr - base);
                    write_string_to_file("dtb_offset", dtbofftmp);
                }
            }

            write_string_to_file("hashtype", hash_type);

            total_read += sizeof(header);
            if(debug > 1) fprintf(stderr, "read: %ld\n", sizeof(header)); // this will harmlessly always show 1660 since it uses boot_img_hdr_v2 for all < v3
            total_read += read_padding(f, sizeof(header));

            write_buffer_to_file("kernel", f, header.kernel_size);

            write_buffer_to_file("ramdisk", f, header.ramdisk_size);

            if(header.second_size != 0) {
                write_buffer_to_file("second", f, header.second_size);
            }

            if(header.dt_size > hdr_ver_max) {
                write_buffer_to_file("dt", f, header.dt_size);
            } else {
                if(header.recovery_dtbo_size != 0) {
                    write_buffer_to_file("recovery_dtbo", f, header.recovery_dtbo_size);
                }
                if(header.dtb_size != 0) {
                    write_buffer_to_file("dtb", f, header.dtb_size);
                }
            }
        } else {
            // boot_img_hdr_v3 and above are no longer backwards compatible

            if(pagesize == 0) {
                pagesize = 0x00001000; // page_size is hardcoded to 4096 in boot_img_hdr_v3 and above
            }

            printf("BOARD_KERNEL_CMDLINE %.*s\n", BOOT_ARGS_SIZE+BOOT_EXTRA_ARGS_SIZE, header.cmdline);
            printf("BOARD_PAGE_SIZE 4096\n");
            print_os_version(header.os_version);
            printf("BOARD_HEADER_VERSION %d\n", header.header_version);
            printf("BOARD_HEADER_SIZE %d\n", header.header_size);

            char cmdlinetmp[BOOT_ARGS_SIZE+BOOT_EXTRA_ARGS_SIZE+1];
            sprintf(cmdlinetmp, "%.*s", BOOT_ARGS_SIZE+BOOT_EXTRA_ARGS_SIZE, header.cmdline);
            cmdlinetmp[BOOT_ARGS_SIZE+BOOT_EXTRA_ARGS_SIZE]='\0';
            write_string_to_file("cmdline", cmdlinetmp);

            char osvertmp[200];
            sprintf(osvertmp, "%d.%d.%d", a, b, c);
            write_string_to_file("os_version", osvertmp);

            char oslvltmp[200];
            sprintf(oslvltmp, "%d-%02d", y, m);
            write_string_to_file("os_patch_level", oslvltmp);

            char hdrvertmp[200];
            sprintf(hdrvertmp, "%d\n", header.header_version); // extra newline to prevent some file editors from interpreting a 2-byte file as Unicode
            write_string_to_file("header_version", hdrvertmp);

            total_read += sizeof(header);
            if(debug > 1) fprintf(stderr, "read: %ld\n", sizeof(header));
            total_read += read_padding(f, sizeof(header));

            write_buffer_to_file("kernel", f, header.kernel_size);

            write_buffer_to_file("ramdisk", f, header.ramdisk_size);
        }
    } else {
        // vendor_boot_img_hdr started at v3 and is not cross-compatible with boot_img_hdr

        fseek(f, i, SEEK_SET);
        vendor_boot_img_hdr_v3 header;
        if(fread(&header, sizeof(header), 1, f)) {};

        base = header.kernel_addr - 0x00008000;
        if(pagesize == 0) {
            pagesize = header.page_size;
        }

        printf("BOARD_VENDOR_CMDLINE %.*s\n", VENDOR_BOOT_ARGS_SIZE, header.cmdline);
        printf("BOARD_VENDOR_BASE 0x%08x\n", base);
        printf("BOARD_NAME %s\n", header.name);
        printf("BOARD_PAGE_SIZE %d\n", header.page_size);
        printf("BOARD_KERNEL_OFFSET 0x%08x\n", header.kernel_addr - base);
        printf("BOARD_RAMDISK_OFFSET 0x%08x\n", header.ramdisk_addr - base);
        printf("BOARD_TAGS_OFFSET 0x%08x\n", header.tags_addr - base);
        printf("BOARD_HEADER_VERSION %d\n", header.header_version);
        printf("BOARD_HEADER_SIZE %d\n", header.header_size);
        printf("BOARD_DTB_SIZE %d\n", header.dtb_size);
        printf("BOARD_DTB_OFFSET 0x%08"PRIx64"\n", header.dtb_addr - base);

        char cmdlinetmp[VENDOR_BOOT_ARGS_SIZE+1];
        sprintf(cmdlinetmp, "%.*s", VENDOR_BOOT_ARGS_SIZE, header.cmdline);
        cmdlinetmp[VENDOR_BOOT_ARGS_SIZE]='\0';
        write_string_to_file("vendor_cmdline", cmdlinetmp);

        write_string_to_file("board", (char *)header.name);

        char basetmp[200];
        sprintf(basetmp, "0x%08x", base);
        write_string_to_file("base", basetmp);

        char pagesizetmp[200];
        sprintf(pagesizetmp, "%d", header.page_size);
        write_string_to_file("pagesize", pagesizetmp);

        char kernelofftmp[200];
        sprintf(kernelofftmp, "0x%08x", header.kernel_addr - base);
        write_string_to_file("kernel_offset", kernelofftmp);

        char ramdiskofftmp[200];
        sprintf(ramdiskofftmp, "0x%08x", header.ramdisk_addr - base);
        write_string_to_file("ramdisk_offset", ramdiskofftmp);

        char tagsofftmp[200];
        sprintf(tagsofftmp, "0x%08x", header.tags_addr - base);
        write_string_to_file("tags_offset", tagsofftmp);

        char hdrvertmp[200];
        sprintf(hdrvertmp, "%d\n", header.header_version); // extra newline to prevent some file editors from interpreting a 2-byte file as Unicode
        write_string_to_file("header_version", hdrvertmp);

        char dtbofftmp[200];
        sprintf(dtbofftmp, "0x%08"PRIx64, header.dtb_addr - base);
        write_string_to_file("dtb_offset", dtbofftmp);

        total_read += sizeof(header);
        if(debug > 1) fprintf(stderr, "read: %ld\n", sizeof(header));
        total_read += read_padding(f, sizeof(header));

        write_buffer_to_file("vendor_ramdisk", f, header.vendor_ramdisk_size);

        write_buffer_to_file("dtb", f, header.dtb_size);
    }

    fclose(f);

    if(debug > 0) fprintf(stderr, "Total Read: %d\n", total_read);
    return 0;
}

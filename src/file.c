#include "file.h"

#include "config.h"
#include "utils.h"

size_t get_file_size(FILE *fp) {
        if (fp == NULL)
                return 0;

        if (fseek(fp, 0, SEEK_END) < 0)
                return 0;

        long res = ftell(fp);
        if (res < 0) {
                fprintf(stderr, "Cannot get size of file\n");
                return 0;
        }

        if (fseek(fp, 0, SEEK_SET) < 0)
                return 0;

        return (size_t)res;
}

int paged_storage_read(byte *dst, FILE *fp, size_t file_size, size_t page_size) {
        size_t nof_pages = file_size / page_size;
        size_t remainder = file_size % page_size;

        // read the pages
        for (; nof_pages > 0; nof_pages--) {
                if (1 != fread(dst, page_size, 1, fp))
                        return ERR_FREAD;
        }
        // read the remainder (bytes)
        if (remainder != fread(dst, 1, remainder, fp))
                return ERR_FREAD;

        return 0;
}

// Writes to fstr_output the encrypted resource. The function can be
// simplified by reading and writing all the bytes with a single
// operation, however, that might fail on platforms where size_t is
// not large enough to store the size of min(resource_size,
// seed_size).  It seems there is no observable difference (in terms
// of performance) between using machine specific page-size vs reading
// the whole resource at once. mmap() as an alternative for fread()
// has been considered, again, apparently no particular performance
// difference for seeds larger than 10MiB.

// If this is a storage write WHY does it have fread?
int paged_storage_write(FILE *fout, FILE *fin, size_t resource_size, byte *out, size_t seed_size,
                        size_t page_size) {

        int write_status = 0;

        size_t min_size  = MIN(resource_size, seed_size);
        size_t nof_pages = min_size / page_size;
        size_t remainder = min_size % page_size;

        // fwrite is slower than fread, so xor is done in memory using
        // a temporary buffer (in the future we can avoid reallocating
        // this buffer for every T, T+1, ...)
        byte *resource_page = checked_malloc(page_size);
        size_t offset       = 0;
        for (; nof_pages > 0; nof_pages--) {
                // read the resource
                if (1 != fread(resource_page, page_size, 1, fin)) {
                        write_status = ERR_FREAD;
                        goto clean_write;
                }
                // xor the resource with the mixed key
                memxor(out + offset, resource_page, page_size);
                // write thre result to fstr_encrypted
                if (1 != fwrite(out + offset, page_size, 1, fout)) {
                        write_status = ERR_FWRITE;
                        goto clean_write;
                }
                offset += page_size;
        }
        // do the previous operations for the remainder of the
        // resource (when the tail is smaller than the seed_size)
        if (remainder != fread(resource_page, 1, remainder, fin)) {
                write_status = ERR_FREAD;
                goto clean_write;
        }
        memxor(out + offset, resource_page, remainder);
        if (remainder != fwrite(out + offset, 1, remainder, fout)) {
                write_status = ERR_FWRITE;
                goto clean_write;
        }

clean_write:
        safe_explicit_bzero(resource_page, page_size);
        free(resource_page);
        return write_status;
}

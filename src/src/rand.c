/*
 *  Copyright (C) 2007 Red Hat, Inc.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the
 *  "Software"), to deal in the Software without restriction, including
 *  without limitation the rights to use, copy, modify, merge, publish,
 *  distribute, sublicense, and/or sell copies of the Software, and to
 *  permit persons to whom the Software is furnished to do so, subject
 *  to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 * 
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
*/

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "nss_compat_ossl.h"

void RAND_add(const void *buf, int num, double entropy)
{
    PK11_RandomUpdate((void *)buf, num);

    return;
}

int RAND_status(void)
{
    /* NSS does its own seeding so this is always true */
    return 1;
}

int RAND_load_file(const char *file, long max_bytes)
{
    long totalread = 0;
    long numread = 0;
    long toread = 0;
    FILE *fp;
    char buf[1024];
    struct stat st;

    if (file == NULL)
        return 0;

    if (stat(file, &st) < 0)
        return 0;

    if (!S_ISREG(st.st_mode)) {
        if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
            if (max_bytes == -1)
                max_bytes = 1024; /* don't read everything from /dev/foo */
        } else
            return 0;
    }
 
    if ((fp = fopen(file, "rb")) != NULL) {
        while (!feof(fp) && (totalread < max_bytes)) {
            if (max_bytes > 0)
                toread = (max_bytes - totalread > 1024) ? 1024 : max_bytes - totalread;
            else
                toread = 1024;
            numread = fread(buf, 1, toread, fp);
            if (numread <= 0)
                break;
            PK11_RandomUpdate(buf, numread);
            totalread += numread;
        }
        fclose(fp);
    }

    return totalread;
}

/* According to man page */
#define RAND_WRITE_BYTES 1024

int RAND_write_file(const char *file)
{
    unsigned char buf[RAND_WRITE_BYTES];
    int total = 0;
    size_t numwrite;
    FILE *fp;

    if ((fp = fopen(file, "wb")) != NULL) {
        chmod(file, 0600);
	if (PK11_GenerateRandom(buf, sizeof (buf)) == SECSuccess) {
	    total = sizeof (buf);
            numwrite = fwrite(buf, 1, total, fp);
            if (numwrite <= 0)
                total = 0;
	}
	fclose(fp);
    }
    return total;
}

const char *RAND_file_name(char *file, size_t num)
{
    char *filename = NULL;
    file[0] = '\0';
    
    /* FIXME: Check $HOME/.rnd too */
    filename = getenv("RANDFILE");

    if (filename && strlen(filename) < num)
        PL_strncpy(file, filename, num);
    else {
        filename = getenv("HOME");
        if (filename && (strlen(filename) + 6 < num)) {
            PR_snprintf(file, num-1, "%s/.rnd", filename);
        } 
    }

    return file;
}

int RAND_egd(const char *path)
{
    return -1; /* EGD not supported */
}

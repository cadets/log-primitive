/*-
 * Copyright (c) 2017 (Ilia Shumailov)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

// The utilities used
#if defined(HAVE_POSIX_FALLOCATE) && !defined(__sun) && !defined(__sun__)
#define _XOPEN_SOURCE 600
#endif
#if !defined(_GNU_SOURCE) && defined(HAVE_LINUX_FALLOC_H)
#define _GNU_SOURCE
#endif
#include <utime.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/types.h>
#include <sys/uio.h>
#endif
#if defined(HAVE_SENDFILE) && (defined(__linux__) || (defined(__sun) && defined(__SVR4)))
#include <sys/sendfile.h>
#endif

#if defined(__APPLE__) && defined(__MACH__) && !defined(__DARWIN__)
#define DARWIN 1
#endif

#if defined(DARWIN) || defined(HAVE_LINUX_FALLOC_H) || defined(HAVE_POSIX_FALLOCATE)
#include <fcntl.h>
#endif

#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <math.h>
#include <string.h>
#include <stdarg.h>

#include "dl_common.h"
#include "dl_memory.h"
#include "dl_utils.h"

segment* ptr_seg;

// Adopted from http://www.doc.ic.ac.uk/~rn710/Installs/otp_src_17.0/erts/emulator/drivers/unix/unix_efile.c
//
int
alloc_big_file(int fd, long int offset, long int length)
{
#if defined HAVE_FALLOCATE
    /* Linux specific, more efficient than posix_fallocate. */
    int ret;

    do {
        ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, (off_t) offset, (off_t) length);
    } while (ret != 0 && errno == EINTR);

#if defined HAVE_POSIX_FALLOCATE
    /* Fallback to posix_fallocate if available. */
    if (ret != 0) {
        ret = call_posix_fallocate(fd, offset, length);
    }
#endif

    return check_error(ret, errInfo);
#elif defined F_PREALLOCATE
    /* Mac OS X specific, equivalent to posix_fallocate. */
    int ret;
    fstore_t fs;

    memset(&fs, 0, sizeof(fs));
    fs.fst_flags = F_ALLOCATECONTIG;
    fs.fst_posmode = F_VOLPOSMODE;
    fs.fst_offset = (off_t) offset;
    fs.fst_length = (off_t) length;

    debug(PRIO_LOW, "Preallocating the file for mac ... ");
    ret = fcntl(fd, F_PREALLOCATE, &fs);
    printf("%d\n", ret);

    if (-1 == ret) {
        debug(PRIO_NORMAL, "Failed to preallocate... Trying to allocate all...\n");
        fs.fst_flags = F_ALLOCATEALL;
        ret = fcntl(fd, F_PREALLOCATE, &fs);
        debug(PRIO_NORMAL, "Returncode: %d\n", ret);


#if defined HAVE_POSIX_FALLOCATE
        /* Fallback to posix_fallocate if available. */
        if (-1 == ret) {
            ret = call_posix_fallocate(fd, offset, length);
        }
#endif
    }

    return ret < 0 ? 0 : 1;
#elif defined HAVE_POSIX_FALLOCATE
    /* Other Unixes, use posix_fallocate if available. */
    return call_posix_fallocate(fd, offset, length) < 0 ? 0 : 1;
#else
    return -1;
#endif
}


#ifdef HAVE_POSIX_FALLOCATE
static int
call_posix_fallocate(int fd, Sint64 offset, Sint64 length)
{
	int ret;

	/*
	* On Linux and Solaris for example, posix_fallocate() returns
	* a positive error number on error and it does not set errno.
	* On FreeBSD however (9.0 at least), it returns -1 on error
	* and it sets errno.
	*/
	do {
		ret = posix_fallocate(fd, (off_t) offset, (off_t) length);
		if (ret > 0) {
			errno = ret;
			ret = -1;
		}
	} while (ret != 0 && errno == EINTR);

	return ret;
}
#endif /* HAVE_POSIX_FALLOCATE */

// Method used to create a partition folder
int
make_folder(const char* partition_name){
    struct stat st;

    if (stat(partition_name, &st) == -1) {
        return mkdir(partition_name, 0777);
    }

    return -1;
}

int
del_folder(const char* partition_name){
    struct stat st;

    if (stat(partition_name, &st) != -1) {
        return remove_directory(partition_name);
    }

    return -1;
}

int
make_file(const char* partition_name, const char* filename){
    char pathFile[128];

    sprintf(pathFile, "%s/%s", partition_name, filename );

    return open(pathFile, O_RDWR | O_APPEND | O_CREAT, 0666);
}

//Method used to create the segment with its log and index files
segment*
make_segment(long int start_offset, long int length,
	const char* partition_name)
{
    char temp[128];
    sprintf(temp, "%ld.log", start_offset);
    int log_file = make_file(partition_name, temp);
    alloc_big_file(log_file, 0, length);

    sprintf(temp, "%ld.index", start_offset);
    int index_file = make_file(partition_name, temp);
    alloc_big_file(index_file, 0,  length);

    segment* seg = (segment*) distlog_alloc(sizeof(segment));
    seg->_log = log_file;
    seg->_index = index_file;

    if (pthread_mutex_init(&seg->mtx, NULL) != 0){
        debug(PRIO_HIGH, "Segment mutex init failed\n");
    }

    return seg;
}

//Method invoked when a new message gets recieved into a segment
int
insert_message(segment* as, char* message, int msg_size)
{
    debug(PRIO_HIGH, "Inserting into the log: '%s'\n", message);

    lseek(as->_log, 0, SEEK_END);
    lseek(as->_index, 0, SEEK_END);

    int len_is = 3 + (int)(floor(log10(index_size_entry)));
    char test[len_is];
    sprintf(test, "%.*d", index_size_entry, msg_size);

    int ret = write(as->_log, test, log_size_entry);

    if(ret < 0){
        return ret;
    }else{
        ret = write(as->_log, message, msg_size); // Attempting to write the message into the file

        char ind[bytes_per_index_entry];
        sprintf(ind, "%.*d%.*d\n", index_size_entry, as->index_position, log_size_entry, as->log_position );

        write(as->_index, ind, strlen(ind));

        as->log_position += ret + log_size_entry;
        as->index_position += 1;

        debug(PRIO_HIGH, "Insert finished\n");
        return ret;
    }
}

segment* get_seg_by_offset(long offset)
{
	return ptr_seg;
}

int
get_message_by_offset(segment* as, int offset, void* saveto)
{
    char buf[bytes_per_index_entry];
    char* bp = buf;

    lseek(as->_index, offset*bytes_per_index_entry, SEEK_SET);

    int ret = read(as->_index, buf, bytes_per_index_entry);

    if(ret > 0){
        int log_offset = atoi(bp+index_size_entry);
        debug(PRIO_LOW, "For requested offset %d log offset is %d\n", offset, log_offset);

        lseek(as->_log, log_offset, SEEK_SET);

        char log_size_field[log_size_entry];
        log_size_field[log_size_entry] = '\0';

        ret = read(as->_log, log_size_field, log_size_entry);
        if (ret > 0){
            int msg_size = atoi(log_size_field);

            ret = read(as->_log, saveto, msg_size);
            return msg_size;
        }
        return ret;
    }else{
        printf("For offset %d no message found.\n", offset);
    }
    return 0;
}

void close_segment(segment* s)
{
    close(s->_log);
    close(s->_index);
}

// adapted from https://stackoverflow.com/questions/2256945/removing-a-non-empty-directory-programmatically-in-c-or-c
int
remove_directory(const char *path)
{
   DIR *d = opendir(path);
   size_t path_len = strlen(path);
   int r = -1;

   if (d)
   {
      struct dirent *p;

      r = 0;

      while (!r && (p=readdir(d)))
      {
          int r2 = -1;
          char *buf;
          size_t len;

          /* Skip the names "." and ".." as we don't want to recurse on them. */
          if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
          {
             continue;
          }

          len = path_len + strlen(p->d_name) + 2;
          buf = (char*) malloc(len);

          if (buf)
          {
             struct stat statbuf;

             snprintf(buf, len, "%s/%s", path, p->d_name);

             if (!stat(buf, &statbuf))
             {
                if (S_ISDIR(statbuf.st_mode))
                {
                   r2 = remove_directory(buf);
                }
                else
                {
                   r2 = unlink(buf);
                }
             }

             free(buf);
          }

          r = r2;
      }

      closedir(d);
   }

   if (!r)
   {
      r = rmdir(path);
   }

   return r;
}


void
debug(int priority, const char* format, ...)
{
	va_list args;

	va_start(args, format);

	if (priority <= PRIO_LOG)
		vprintf(format, args);

	va_end(args);
}

void
lock_seg(struct segment* seg)
{
	pthread_mutex_lock(&seg->mtx);
}

void
ulock_seg(struct segment* seg)
{
	pthread_mutex_unlock(&seg->mtx);
}

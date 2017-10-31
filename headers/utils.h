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

// The header file with the used utilities

#ifndef UTILS_H
#define UTILS_H

#include <pthread.h>
#include <dirent.h>
#include "../headers/protocol_common.h"

#define MAX_FILENAME_SIZE 30


static int index_size_entry = 8;
static int log_size_entry = 8;
static int bytes_per_index_entry = 17;//index_size_entry + log_size_entry + 1;
static int segments_per_partition = 64;

enum topic_status{
	UNKNOWN_TOPIC = 1 << 1,
	LEADER_NOT_AVAILABLE = 1 << 2,
	INVALID_TOPIC = 1 << 3,
	TOPIC_AUTHORIZATION_FAILED = 1 << 4
};


struct segment{
    // Maybe split into single seeker and single inserter? That way one should be able to insert and get silmultaniously
    int _log;
    int _index;

    int log_position; // Current position in the log
    int index_position; // Current offset position in the log

    pthread_mutex_t mtx;
};

typedef struct segment segment;

struct partition{
    struct partition* active_segment;
    char* id;
};

struct utils_config{
    char topics_folder[MAX_FILENAME_SIZE];
};


typedef struct partition partition;

int alloc_big_file(int fd, long int offset, long int length);

//Managing partitions
int make_folder(const char* partition_name);
int del_folder(const char* partition_name);

// Managing segments
segment* make_segment(long int start_offset, long int length, const char* partition_name);
void close_segment(segment* s);

// Managing messages
int insert_message(segment* as, char* message, int msg_size);

int get_message_by_offset(segment* as, int offset, void* saveto);
int remove_directory(const char *path);

#define PRIO_HIGH   1 << 1
#define PRIO_NORMAL 1 << 2
#define PRIO_LOW    1 << 3

extern unsigned short PRIO_LOG;

void debug(int priority, const char* format, ...);

void lock_seg(struct segment* seg);
void ulock_seg(struct segment* seg);
#endif

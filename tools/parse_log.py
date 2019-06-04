#-
# Copyright (c) 2018-2019 (Graeme Jenkinson)
# All rights reserved.
#
# This software was developed by BAE Systems, the University of Cambridge
# Computer Laboratory, and Memorial University under DARPA/AFRL contract
# FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
# (TC) research program.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import argparse
import record_batch
import struct
import zlib

# The index is 16-bytes long: <offset>,<size>
LOG_IDX_SIZE = 16 

# The header is 12-bytes long: <offset>,<size>
LOG_HDR_SIZE = 12 

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action='store_true', help="verbose output")
    parser.add_argument("log", help="input log file")
    parser.add_argument("index", help="output index file")
    parser.add_argument("offset", type=int, help="requested log offset")
    args = parser.parse_args()

    # Open the log and index files for reading
    with open(args.log, "rb") as log:
        with open(args.index, "rb") as idx:
            
            # Lookup the requested offset
            idx.seek(args.offset * LOG_IDX_SIZE);
            idx_val = idx.read(LOG_IDX_SIZE)
            if not idx_val: 
               exit() 
            
            # Unpack the value of the index (offset, off_t)
            (idx_offset, poffset) = struct.unpack(">qq", idx_val);

            # Read LOG_HDR_SIZE sizes from the position the log;
            # header contains the log offset and record
            # size in bigendian format
            log.seek(poffset);
            header = log.read(LOG_HDR_SIZE)
            if not header: 
              exit() 
            
            # Unpack the raw data
            (log_offset, size) = struct.unpack(">qi", header);
            
            # Advance past the header and read the entry in the log
            log.seek(poffset) # + LOG_HDR_SIZE)
            message_set = log.read(size + LOG_HDR_SIZE)
            if not message_set: 
              exit() 
        
            # Decode and print the RecordBatch
            rb = record_batch.decode(message_set)
            print rb

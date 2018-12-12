#-
# Copyright (c) 2018 (Graeme Jenkinson)
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

import argparse;
import struct;
import zlib;

# The header is 8-bytes long: <offset>,<size>
LOG_HDR_SIZE = 8

# The index is 12-bytes long: <offset>,<size>
LOG_IDX_SIZE = 12 

class MessageSet:

    def __init__(self):
        self.messages = []

    def add_message(self, message):
        self.messages.append(message)

class Message:

    def __init__(self, key_len, key, value_len, value):
       self.key_len = key_len
       self.key = key
       self.value_len = value_len
       self.value = value

def message_set_decode(raw_data):

    message_set = MessageSet()
    message = message_decode(raw_data)
    message_set.add_message(message)

    return message_set

def message_decode(raw_data):

    raw_data_offset = 0

    # Decode the Message offset, size, CRC, magic byte and attributes
    (offset, size, crc, magic, attributes) = struct.unpack(">qiibb",
            raw_data[0:18]);
    raw_data_offset += 18;

    if magic == 0x00 or magic == 0x01:
        # Decode the Message timestamp
        timestamp = struct.unpack_from(">q", raw_data, raw_data_offset)[0]
        raw_data_offset += 8

    # Decode the primitve Byte array holding the Message key
    key_len = struct.unpack_from(">i", raw_data, raw_data_offset)[0]
    raw_data_offset += 4
    if key_len == -1:
        key = None
    else:
        key = raw_data[raw_data_offset:raw_data_offset+key_len]
        offset += key_len 

    # Decode the primitve Byte array holding the Message value 
    value_len = struct.unpack_from(">i", raw_data, raw_data_offset)[0]
    raw_data_offset += 4
    if value_len == -1:
        value = None
    else:
        value = raw_data[raw_data_offset:raw_data_offset+value_len]
        raw_data_offset += value_len 

    # Uncompress value if compressed
    if attributes & 0x01:
        value = zlib.decompress(value, 31)

    return Message(key_len, key, value_len, value)

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
            (idx_offset, poffset) = struct.unpack(">Iq", idx_val);

            # Read LOG_HDR_SIZE sizes from the position the log;
            # header contains the log offset and record
            # size in bigendian format
            log.seek(poffset);
            header = log.read(LOG_HDR_SIZE)
            if not header: 
              exit() 
            
            # Unpack the raw data
            (log_offset, size) = struct.unpack(">Ii", header);

            if idx_offset != log_offset:
                exit();

            # Advance past the header and read the entry in the log
            log.seek(poffset + LOG_HDR_SIZE)
            message_set = log.read(size)
            if not message_set: 
              exit() 

            # Decode the MessageSet
            ms = message_set_decode(message_set)

            # Display the returned MessageSet
            for m in ms.messages:
                if m.key is not None:
                    if args.verbose is True:
                        print "Key = " + ''.join('<0x{:02x}>'.format(x) for x in bytearray(m.key))
                    else:
                        print "Key = {}".format(m.key)
                if args.verbose is True:
                    print "Value = " + ''.join('<0x{:02x}>'.format(x) for x in bytearray(m.value))
                else:
                    print "Value = {}".format(m.value)

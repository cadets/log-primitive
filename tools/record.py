#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019 (Graeme Jenkinson)
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

import struct
import sys
import varint
import record_header 
   
class RecordException(Exception):
    pass

class RecordInvalidLengthException(RecordException):
    pass

# Conversion between number of bytes and format Python struct format codes 
def varint2fmt(v): 
    if v < 0x10000:
        if v < 0x100:
            return 'b'
        else:
            return 'h'
    else:
        if v < 0x100000000L:
            return 'i'
        else:
            return 'q'

def clz(v):
    if v == 0:
        return 31
    else:
        n = 0
        while (v & 0x80000000) == 0:
            n = n + 1
            v <<= 1
        return n

def clz64(v):
    if v == 0:
        return 63 
    else:
        n = 0
        while (v & 0x8000000000000000) == 0:
            n = n + 1
            v <<= 1
        return n


varint_size_map = [
        1, 1 ,1, 1, 1, 1, 1, 2,
        2, 2, 2, 2, 2, 2, 3, 3,
        3, 3, 3, 3, 3, 4, 4, 4,
        4, 4, 4, 4, 5, 5 ,5, 5,
        5, 5, 5, 6 ,6, 6, 6, 6,
        6, 6, 7, 7, 7, 7, 7, 7,
        7, 8, 8, 8, 8, 8, 8, 8,
        9, 9, 9, 9, 9, 9, 9, 10]

# Decode a Record.
def decode(b):
    # Decode the Length
    length = varint.decode_bytes(b)
    size = varint_size_map[31 - clz(length)]
    length = (length >> 1) ^ -(length & 1)

    # Verfiy the Length of the Record
    if length + size > len(b):
        raise RecordInvalidLengthException(\
                "BatchLength {} exceeds record length {}".format( \
                length, len(b)))

    # Encode the Attributes (unused)
    nsize = struct.calcsize("> b")
    attr = struct.unpack("> b", b[size:size+nsize])
    size += nsize

    # Decode the TimestampDelta 
    ts_delta = varint.decode_bytes(b[size:])
    size += varint_size_map[31 - clz(ts_delta)]
    ts_delta = (ts_delta >> 1) ^ -(ts_delta & 1)

    # Decode the OffsetDelta
    offs_delta = varint.decode_bytes(b[size:])
    size += varint_size_map[31 - clz(offs_delta)]
    offs_delta = (offs_delta >> 1) ^ -(offs_delta & 1)

    # Decode the KeyLength and Key
    klen = varint.decode_bytes(b[size:])
    nsize = varint_size_map[31 - clz(klen)]
    klen = (klen >> 1) ^ -(klen & 1)
    size += nsize
    (k, ) = struct.unpack("> {}s".format(klen), b[size:size+klen])
    size += klen
   
    # Decode the ValueLength and Value
    vlen = varint.decode_bytes(b[size:])
    nsize = varint_size_map[31 - clz(vlen)]
    vlen = (vlen >> 1) ^ -(vlen & 1)
    size += nsize
    (v, ) = struct.unpack("> {}s".format(vlen), b[size:size+vlen])
    size += vlen 
    
    # Decode the number of Headers
    nhdrs = varint.decode_bytes(b[size:])
    nsize = varint_size_map[31 - clz(nhdrs)]
    nhdrs = (nhdrs >> 1) ^ -(nhdrs & 1)
    size += nsize

    headers = []
    for i in range(0, nhdrs):
        (hdr, hdr_size) = record_header.decode(b[size:])
        headers.append(hdr)
        size += hdr_size

    return (Record(ts_delta, offs_delta, k, v, headers) ,size)

# Kafka Record
class Record():

    def __init__(self, ts_delta, offs_delta, key, value, headers=[]):
        self._ts_delta = ts_delta 
        self._offs_delta = offs_delta
        self._key = key 
        self._value = value 
        self._headers = headers

    def __eq__(self, other):
        return self._ts_delta == other._ts_delta and \
                self._offs_delta == other._offs_delta and \
                self._key == other._key and self._value == other._value

    def __str__(self):
        return "<TimeStampDelta = {},\nOffsetDelta = {},\nKey = {}," \
                "\nValue = {},\nHeaders = {}>".format(self._ts_delta, \
                self._offs_delta, self._key, self._value, self._headers) 

    def __repr__(self):
        return self.__str__ 

    def add_header(self, header):
        self._headers.append(header)

    def set_offset_delta(self, offs_delta):
        self._offs_delta = offs_delta

    def set_timestamp_delta(self, ts_delta):
        self._ts_delta = ts_delta

    # Encode the Record
    def encode(self):
        # Encode the Attributes (unused)
        b = struct.pack("> b", 0)

        # Encode the TimeStampDelta
        ts_delta_var = ord(varint.encode((self._ts_delta << 1) ^ \
                (self._ts_delta >> 31)))
        b += struct.pack("> {}".format(varint2fmt(ts_delta_var)),
            ts_delta_var)

        # Encode the OffsetDelta
        offs_delta_var = ord(varint.encode((self._offs_delta << 1) ^ \
                (self._offs_delta >> 31)))
        b += struct.pack("> {}".format(varint2fmt(offs_delta_var)), \
                offs_delta_var)

        # Encode the Record Key and Value
        klen_var = ord(varint.encode((len(self._key) << 1) ^ \
                (len(self._key) >> 31)))
        vlen_var = ord(varint.encode((len(self._value) << 1) ^\
                (len(self._value) >> 31)))
        b += struct.pack("> {} {}s {} {}s".format(
            varint2fmt(klen_var), len(self._key),
            varint2fmt(vlen_var), len(self._value)),
            klen_var, self._key, vlen_var, self._value)

        # Encode the number of Headers
        nhdrs_var = ord(varint.encode((len(self._headers) << 1) ^ \
                (len(self._headers) >> 31)))
        b += struct.pack("> {}".format(varint2fmt(nhdrs_var)), \
                nhdrs_var)

        # Encode the Headers
        for header in self._headers:
            b += header.encode()

        # Encode the Length 
        len_var = ord(varint.encode(((len(b) << 1) ^ (len(b) >> 31))))

        # Return the encoded Record
        return struct.pack("> {}".format(varint2fmt(len_var)), len_var) + b

if __name__ ==  "__main__":

    # Construct a Record
    r = Record(0, 0, "key", "value", [])
    print "Record: {}".format(r)

    # Encode the RecordHeader
    r_encoded = r.encode()
    print 'EncodedRecord: ' + \
            ''.join( [ "%02X " % ord(i) for i in r_encoded] ).strip()

    # Decode the Record
    (r_decoded, _) = decode(r_encoded)
    print "Record: {}".format(r_decoded)

    # Check that the decoded Record matches the original
    print r == r_decoded

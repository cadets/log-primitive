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
   
# Conversion between number of bytes and format Python struct format codes 
def val2fmt(v): 
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

# Decode a RecordHeader.
def decode(b):
    # Decode the KeyLength (signed Varint, ZigZag encoded)
    klen = varint.decode_bytes(b)
    klen = (klen >> 1) ^ -(klen & 1)

    # Decode the Key
    print klen
    print val2fmt(klen)
    ksize = struct.calcsize("> {} {}s".format(val2fmt(klen), klen))
    (_, k) = struct.unpack("> {} {}s".format(val2fmt(klen),
        klen), b[:ksize])
    
    # Decode the ValueLength (signed Varint, ZigZag encoded)
    vlen = varint.decode_bytes(b[ksize:])
    vlen = (vlen >> 1) ^ -(vlen & 1)

    # Decode the Value 
    vsize = struct.calcsize("> {} {}s".format(val2fmt(vlen), vlen))
    (_, v) = struct.unpack("> {} {}s".format(val2fmt(vlen),
        vlen), b[ksize:ksize+vsize])

    # Return the decoded RecordHeader
    return (RecordHeader(k, v), ksize+vsize)

# Kafka RecordHeader
class RecordHeader():
        
    def __init__(self, key=None, value=None):
        self._key = key
        self._value = value

    def __eq__(self, other):
        return self._key == other._key and self._value == other._value

    def __str__(self):
        return "<key = {}, value = {}>".format(self._key, self._value) 

    def __repr__(self):
        return self.__str__ 

    # Encode a RecordHeader
    def encode(self):
        # Encode the RecordHeader Key and Value
        klen_var = ord(varint.encode((len(self._key) << 1) ^ \
                (len(self._key) >> 31)))
        vlen_var = ord(varint.encode((len(self._value) << 1) ^ \
                (len(self._value) >> 31)))

        # Return the encoded RecordHeader
        return struct.pack("> {} {}s {} {}s".format(
            val2fmt(klen_var), len(self._key),
            val2fmt(vlen_var), len(self._value)),
            klen_var, self._key, vlen_var, self._value)

if __name__ ==  "__main__":

    # Construct a RecordHeader
    rb = RecordHeader("key", "value")
    print 'RecordHeader: {}'.format(rb)

    # Encode the RecordHeader
    rb_encoded = rb.encode()
    print 'Encoded RecordHeader: ' + \
            ''.join( [ "%02X " % ord(i) for i in rb_encoded] ).strip()

    # Decode the RecordHeader
    (rb_decoded, _) = decode(rb_encoded)
    print 'RecordHeader: {}'.format(rb_decoded)

    # Check that the decoded Record~header matches the original
    print rb == rb_decoded

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

import crc32c 
import record
import struct
import sys
import varint
import zlib
 
class RecordBatchException(Exception):
    pass

class RecordBatchInvalidLengthException(RecordBatchException):
    pass

class RecordBatchInvalidMagicException(RecordBatchException):
    pass

class RecordBatchInvalidCrcException(RecordBatchException):
    pass

class RecordBatchInvalidLastOffsetException(RecordBatchException):
    pass

# Decode RecordBatch
def decode(b):
    size = 0

    # Decode the BaseOffset, BatchLength, Magic and CRC
    nsize = struct.calcsize("> q i i b I"); 
    (base_offset, batch_length, part_ldr_epoch, magic, crc) = \
            struct.unpack("> q i i b I", b[size:size+nsize])
    size += nsize

    # Validate the BatchLength
    if batch_length != (len(b) - struct.calcsize("> q i")):
        raise RecordBatchInvaliidLengthException( \
                "Invalid BatchLength {}".format(batch_length))

    # Validate the Magic byte
    if magic != 2:
        raise RecordBatchInvalidMagicException( \
                "Invalid Magic byte {}".format(magic))

    # Validate the CRC
    calculated_crc = crc32c.crc32(b[size:])
    if crc != calculated_crc:
        raise RecordBatchInvalidCRCException( \
                "Invalid CRC {} != {}".format(crc, calculated_crc))
    
    # Decode the Attributes, LastOffsetDelta, FirstTimestamp, MaxTimestamp,
    # ProducerId, ProducerEpoch, BaseSequence
    nsize = struct.calcsize("> h i q q q h i"); 
    (attributes, last_offset_delta, first_timestamp, max_timestamp, producer_id, \
            producer_epoch, base_sequence) = struct.unpack("> h i q q q h i", \
            b[size:size+nsize])
    size += nsize

    # Decode the number of Records 
    nsize = struct.calcsize("> i"); 
    (nrecs, ) = struct.unpack("> i", b[size:size+nsize]); 
    size += nsize
   
    # Validate the Record size
    if nrecs != last_offset_delta + 1:
        raise RecordBatchInvalidLastOffsetException( \
                "LastOffset and number of Records inconsistent.")

    if attributes == 0x01:
        # Decompress the Records
        decompress = zlib.decompressobj(zlib.MAX_WBITS | 16)
        encoded_records = decompress.decompress(b[size:])
        encoded_records += decompress.flush()
    else:
        encoded_records = decompress.decompress(b[size:])

    # Decode each of the Records
    records = []
    rec_offset = 0
    for i in range(0, nrecs):
        # Need to return the position in the buffer
        (rec, rec_size) = record.decode(encoded_records[rec_offset:])
        records.append(rec)
        rec_offset += rec_size

    # Return the decoded RecordBatch
    return RecordBatch(first_timestamp, max_timestamp, last_offset_delta, \
            records)

class RecordBatch():

    _first_timestamp = 0
    _max_timestamp = 0
    _last_offset_delta = -1
    _records = []

    def __init__(self, first_timestamp = 0, max_timestamp = 0, \
            last_offset_delta = -1, records = []):
        self._first_timestamp = first_timestamp
        self._max_timestamp = max_timestamp
        self._last_offset_delta = last_offset_delta
        self._records = records

    def __eq__(self, other):
        return self._first_timestamp == other._first_timestamp  and \
                self._max_timestamp == other._max_timestamp and \
                self._last_offset_delta == other._last_offset_delta

    def __str__(self):
        s = "<\n"
        s += "FirstTimestamp {},\n".format(self._first_timestamp)
        s += "MaxTimestamp {},\n".format(self._max_timestamp)
        s += "LastOffsetDelta {},\n".format(self._last_offset_delta)
        for r in self._records:
            s += r.__str__()
        s += "\n>"
        return s

    def __repr__(self):
        return self.__str__ 

    def add_record(self, record):
        record.set_offset_delta(self._last_offset_delta)
        self._last_offset_delta = self._last_offset_delta + 1

        record.set_timestamp_delta(0)
        self._first_timestamp = 0
        self._max_timestamp = 0

        self._records.append(record)

    def encode(self):
        b = ""
        rb = ""

        # Encode the Records
        encoded_records = ""
        for record in self._records:
            encoded_records += record.encode()

        # Compress the encoded records using GZIP
        compress = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, \
                zlib.MAX_WBITS | 16)
        compressed_records = compress.compress(encoded_records)
        compressed_records += compress.flush()

        # Encode the Attributes
        if len(encoded_records) <= len(compressed_records):
            b += struct.pack("> h", 0)
        else:
            b += struct.pack("> h", 1)

        # Encode the LastOffsetDelta
        b += struct.pack("> i", self._last_offset_delta)

        # Encode the FirstTimestamp
        b += struct.pack("> q", self._first_timestamp)

        # Encode the MaxTimestamp
        b += struct.pack("> q", self._max_timestamp)

        # Encode the ProducerId
        b += struct.pack("> q", -1);

        # Encode the ProducerEpcoh
        b += struct.pack("> h", -1);

        # Encode the BaseSequence 
        b += struct.pack("> i", -1);

        # Encode the Records
        b += struct.pack("> i", len(self._records))
        if len(encoded_records) <= len(compressed_records):
            b += encoded_records
        else:
            b += compressed_records

        # Encode the BaseOffset
        rb += struct.pack("> q", 0)

        # Encode the BatchLength
        rb += struct.pack("> i", len(b) + struct.calcsize("> i b I"))

        # Encode the ParitionLeaderEpoch
        rb += struct.pack("> i", 0)
 
        # Encode the Magic
        rb += struct.pack("> b", 2)

        # Encode the CRC
        rb += struct.pack("> I", crc32c.crc32(b))

        # Append the CRC'd part of the RecordBatch
        rb += b;

        return rb 


if __name__ ==  "__main__":

    # Construct a RecordBatch
    rb = RecordBatch()

    # Construct a Record and add it to the RecordBatch
    r = record.Record(0, 0, "key", "valuevaluevaluevaluevaluevalue", [])
    rb.add_record(r)
    print "Record: {}".format(r)

    # Encode the RecordBatch
    rb_encoded = rb.encode()
    print 'Encoded RecordBatch: ' + \
            ''.join( [ "%02X " % ord(i) for i in rb_encoded] ).strip()

    # Decode the RecordBatch
    rb_decoded = decode(rb_encoded)
    print "RecordBatch: {}".format(rb)
    print "RecordBatch: {}".format(rb_decoded)

    # Check that the decoded RecordBatch matches the original
    print rb == rb_decoded

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

# The header is 8-bytes long: <offset>,<size>
LOG_HDR_SIZE = 8

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("log", help="input log file")
    parser.add_argument("index", help="output index file")
    args = parser.parse_args()

    poffset = 0;

    # Open the log file for reading and the index for writing
    with open(args.log, "rb") as log:
        with open(args.index, "wb+") as idx:

            while True:
                # Read LOG_HDR_SIZE sizes from the current position in
                # the log; raw_data contains the log offset and record
                # size in bigendian format
                log.seek(poffset);
                raw_data = log.read(LOG_HDR_SIZE)
                if not raw_data: 
                    break

                # Unpack the raw data
                (offset, size) = struct.unpack(">Ii", raw_data);

                # Write the log offset and correspondinging physical
                # location in the log file to the index
                data = struct.pack(">II", offset, poffset)
                idx.write(data)

                # Advance to the next entry in the log
                poffset += (LOG_HDR_SIZE + size);

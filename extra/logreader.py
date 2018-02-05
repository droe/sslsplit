#!/usr/bin/env python
# vim: set ft=python list et ts=8 sts=4 sw=4:

# SSLsplit contributed code:  Log parser for sslsplit -L
# This script reads the log from standard input and parses it.
# Standard input can point to a file or a named pipe.

# Copyright (C) 2015, Maciej Kotowicz <mak@lokalhost.pl>.
# Copyright (C) 2015, Daniel Roethlisberger <daniel@roe.ch>.
# All rights reserved.
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
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys
import os
import select
import re

def read_line(f):
    """Read a single line from a file stream; return empty string on EOF"""
    buf = ''
    while not buf.endswith("\n"):
        r, w, e = select.select([f], [], [])
        if r:
            nextbyte = f.read(1)
            if not nextbyte:
                return ''
            buf += nextbyte
        else:
            break
    return buf

def read_count(f, n):
    """Read n bytes from a file stream; return empty string on EOF"""
    buf = ''
    while len(buf) < n:
        nextchunk = f.read(n - len(buf))
        if not nextchunk:
            return ''
        buf += nextchunk
    return buf

class LogSyntaxError(Exception):
    """SSLsplit log file contains unexpected syntax"""
    pass

def parse_header(line):
    """Parse the header line into a dict with useful fields"""
    # 2015-09-27 14:55:41 UTC [192.0.2.1]:56721 -> [192.0.2.2]:443 (37):
    m = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+) \[(.+?)\]:(\d+) -> \[(.+?)\]:(\d+) \((\d+|EOF)\):?', line)
    if not m:
        raise LogSyntaxError(line)
    res = {}
    res['timestamp'] = m.group(1)
    res['src_addr'] = m.group(2)
    res['src_port'] = int(m.group(3))
    res['dst_addr'] = m.group(4)
    res['dst_port'] = int(m.group(5))
    if m.group(6) == 'EOF':
        res['eof'] = True
    else:
        res['eof'] = False
        res['size'] = int(m.group(6))
    return res

def parse_log(f):
    """Read log entries from file stream in blocking mode until EOF"""
    while True:
        line = read_line(f)
        if not line:
            break
        res = parse_header(line)
        if (not res['eof']):
            res['data'] = read_count(f, res['size'])
        yield res

if __name__ == '__main__':
    for result in parse_log(sys.stdin):
        print result


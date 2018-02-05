#!/usr/bin/env python
# vim: set ft=python list et ts=8 sts=4 sw=4:

# SSLsplit contributed code:  Converts sslsplit -L log to PCAP.
# This script reads the log from standard input and converts it to a
# corresponding PCAP file.  Information which is not contained in the
# log, such as TCP sequence numbers, IP ID etc are emulated and do not
# correspond to the values in the original traffic.  Note that the
# algorithms used do not scale well for large volumes of traffic.

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
import datetime
import random
import scapy
from scapy.utils import PcapWriter
from scapy.all import Ether, IP, TCP

import logreader

# avoid requiring root and waiting for on-the-wire timeouts (issue #169)
def getmacbyip(ip, chainCC=0):
    return "11:22:33:44:55:66"
scapy.layers.l2.getmacbyip = getmacbyip

def parse_timestamp(s):
    return datetime.datetime.strptime(s, '%Y-%m-%d %H:%M:%S %Z')

def chunks(s, sz):
    return (s[0+i:sz+i] for i in range(0, len(s), sz))

class NetworkStack():
    """Emulated network stack, processing log entries into network packets"""
    class ConnState():
        """State for a single TCP connection"""
        def __init__(self, logentry, tm, ctx):
            self.src_addr = logentry['src_addr']
            self.src_port = logentry['src_port']
            self.dst_addr = logentry['dst_addr']
            self.dst_port = logentry['dst_port']
            self.tm = tm
            self._ctx = ctx

        def touch(self, tm):
            if self.tm < tm:
                self.tm = tm

        def _write_packet(self, pkt):
            pkt.time = (self.tm - datetime.datetime(1970, 1, 1)).total_seconds()
            self._ctx.pcap.write(pkt)
            self._ctx.last_packet_tm = self.tm

        def _seq(self, addr, port, inc):
            if self.src_addr == addr and self.src_port == port:
                seq = self.src_seq
                ack = self.dst_seq
                self.src_seq += inc
            else:
                seq = self.dst_seq
                ack = self.src_seq
                self.dst_seq += inc
            return (seq, ack)

        def syn(self):
            """Send a TCP SYN handshake, opeining the connection"""
            self.src_seq = random.randint(1024, (2**32)-1)
            self.dst_seq = random.randint(1024, (2**32)-1)

            self._write_packet(
                    Ether()/
                    IP(src=self.src_addr, dst=self.dst_addr)/
                    TCP(flags='S',
                        sport=self.src_port, dport=self.dst_port,
                        seq=self.src_seq)
                    )
            self.src_seq += 1

            self._write_packet(
                    Ether()/
                    IP(src=self.dst_addr, dst=self.src_addr)/
                    TCP(flags='SA',
                        sport=self.dst_port, dport=self.src_port,
                        seq=self.dst_seq, ack=self.src_seq)
                    )
            self.dst_seq += 1

            self._write_packet(
                    Ether()/
                    IP(src=self.src_addr, dst=self.dst_addr)/
                    TCP(flags='A',
                        sport=self.src_port, dport=self.dst_port,
                        seq=self.src_seq, ack=self.dst_seq)
                    )

        def fin(self):
            """Send a TCP FIN handshake, closing current connection"""
            self._write_packet(
                    Ether()/
                    IP(src=self.src_addr, dst=self.dst_addr)/
                    TCP(flags="FA",
                        sport=self.src_port, dport=self.dst_port,
                        seq=self.src_seq, ack=self.dst_seq)
                    )
            self.src_seq += 1
            self._write_packet(
                    Ether()/
                    IP(src=self.dst_addr, dst=self.src_addr)/
                    TCP(flags='A',
                        sport=self.dst_port, dport=self.src_port,
                        seq=self.dst_seq, ack=self.src_seq)
                    )

        def data(self, logentry):
            """Send a TCP data segment within the connection"""
            for segment in chunks(logentry['data'], self._ctx.mss):
                seq, ack = self._seq(logentry['src_addr'],
                                     logentry['src_port'], len(segment))
                self._write_packet(
                        Ether()/
                        IP(src=logentry['src_addr'], dst=logentry['dst_addr'])/
                        TCP(flags='PA',
                            sport=logentry['src_port'],
                            dport=logentry['dst_port'],
                            seq=seq, ack=ack)/
                        segment
                        )

    def __init__(self, outfile, mtu=1500):
        self.pcap = PcapWriter(filename=outfile, linktype=1)
        self.mss = mtu - 40
        self.connstate = {}
        self.last_packet_tm = datetime.datetime(1970, 1, 1, 0, 0, 0)
        self.last_timeout_tm = datetime.datetime(1970, 1, 1, 0, 0, 0)

    def _make5tuple(self, logentry):
        """Construct a canonical per-connection 5-tuple"""
        if (logentry['src_addr'] < logentry['dst_addr']) or \
           (logentry['src_addr'] == logentry['dst_addr'] and \
            logentry['src_port'] < logentry['dst_port']):
            return "tcp|%s|%d|%s|%d" % (logentry['src_addr'],
                                        logentry['src_port'],
                                        logentry['dst_addr'],
                                        logentry['dst_port'])
        else:
            return "tcp|%s|%d|%s|%d" % (logentry['dst_addr'],
                                        logentry['dst_port'],
                                        logentry['src_addr'],
                                        logentry['src_port'])

    # Note that the chosen data structure for the internal state scales badly
    # for large numbers of connections:  O(n) search every minute.  This needs
    # to be rewritten using better data structures for scalability.

    def add(self, logentry):
        """Process a log entry, keeping internal state"""
        tm = parse_timestamp(logentry['timestamp'])
        conn5tuple = self._make5tuple(logentry)

        if logentry['eof']:
            if conn5tuple in self.connstate:
                self.connstate[conn5tuple].fin()
                del self.connstate[conn5tuple]
        else:
            if not conn5tuple in self.connstate:
                self.connstate[conn5tuple] = NetworkStack.ConnState(logentry,
                                                                    tm,
                                                                    self)
                self.connstate[conn5tuple].syn()
            else:
                self.connstate[conn5tuple].touch(tm)
            self.connstate[conn5tuple].data(logentry)

        # at most every 60s, time out old connections (should not happen)
        if tm > self.last_timeout_tm + datetime.timedelta(0, 1, 0):
            for conn in self.connstate:
                if self.last_timeout_tm > self.connstate[conn5tuple].tm + \
                        datetime.timedelta(0, 1, 0):
                    self.connstate[conn5tuple].fin()
                    del self.connstate[conn5tuple]
            self.last_timeout_tm = tm

    def done(self):
        """We are done, all active connections can be closed"""
        for conn in self.connstate:
            self.connstate[conn].touch(self.last_packet_tm)
            self.connstate[conn].fin()
        self.pcap.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: %s example.pcap <example.log\n' % sys.argv[0])
        sys.exit(-1)

    netemu = NetworkStack(sys.argv[1])
    for logentry in logreader.parse_log(sys.stdin):
        netemu.add(logentry)
    netemu.done()


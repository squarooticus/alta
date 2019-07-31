#! /usr/bin/python3
#
# MIT License
#
# Copyright (C) 2019 Akamai Technologies, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .common import *

class Producer:
    def __init__(self, scheme):
        self._scheme = scheme
        self._stream = []
        self._hashes = {}
        self._next_index = 0
        self._last_index = None

    def push_payload(self, payload):
        # FIXME: sequence number is going to want to be a complex type to deal
        # with rollover
        index = payload.index
        if index != self._next_index:
            raise OutOfOrder()
        self._stream.append(payload)
        self._next_index += 1
        try:
            self._payload_hash(index)
        except Pending:
            pass

    def payloads_ready(self):
        while self._stream and (self._last_index or \
                self._scheme.is_ready(self._earliest_index(), self._latest_index())):
            p = self._stream[0]
            try:
                h = self._payload_hash(p.index)
            except Pending as v:
                # This is an error condition: the scheme thinks we're ready but
                # we're missing a chained hash somewhere. Bomb.
                raise SchemeError() from v
            self._stream.pop(0)
            yield p
        self._expire_old_state()

    def shutdown(self):
        self._last_index = self._latest_index()

    def _latest_index(self):
        if self._last_index:
            return self._last_index
        if not self._stream:
            raise OutOfRange()
        return self._stream[-1].index

    def _earliest_index(self):
        if not self._stream:
            raise OutOfRange()
        return self._stream[0].index

    def _payload_hash(self, index):
        if index in self._hashes:
            if self._hashes[index] == Pending:
                raise SchemeError()
            return self._hashes[index]
        if index < self._earliest_index() or (self._last_index and index > self._last_index):
            raise IndexError()
        if index > self._latest_index():
            raise Pending()
        self._hashes[index] = Pending
        try:
            self._hashes[index] = self._compute_payload_hash(index)
        except:
            del self._hashes[index]
            raise
        return self._hashes[index]

    def _compute_payload_hash(self, index):
        p = self._get_payload(index)
        incomplete = False
        for src_index in self._scheme.sources(index, 0, self._last_index):
            if not p.auth_tag.get_chained_hash(src_index):
                try:
                    p.auth_tag.chain_payload_hash(src_index, self._payload_hash(src_index))
                except Pending:
                    incomplete = True
        if incomplete:
            raise Pending()
        return p.hash()

    def _get_payload(self, index):
        try:
            if self._earliest_index() <= index <= self._latest_index():
                return self._stream[index - self._earliest_index()]
            else:
                raise IndexError()
        except OutOfRange as v:
            raise IndexError() from v

    def _expire_old_state(self):
        if self._last_index:
            self._hashes.clear()
        else:
            for i in [ index for index in self._hashes
                    if not self._scheme.in_write_window(index, self._latest_index()) ]:
                self._hashes.pop(i, None)

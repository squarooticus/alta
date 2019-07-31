#! /usr/bin/python3
#
# MIT License
#
# Copyright (c) Akamai Technologies, Inc. 2019
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

from .auth_tag import AuthTagEO
from .common import *

class Consumer:
    def __init__(self, pre_lv_window=128, post_lv_window=128):
        self._pre_lv_window = pre_lv_window
        self._post_lv_window = post_lv_window
        self._payloads = {}
        self._verified_hashes = {}
        self._latest_verified_index = 0

    def push_payload(self, payload, assume_verified=False):
        index = payload.index
        # FIXME: a forged payload will DoS future arrivals of legit payloads with
        # the same sequence number: probably need to keep track of all variants
        # of a payload until one is verified, and then toss the others.
        self._payloads.setdefault(index, payload)
        h = payload.hash()
        vh = self._verified_hashes.get(index, None)
        # FIXME: Replace error logging with some kind of error queue
        if vh not in (None, h):
            print('ERROR: newly received payload %d does not match previously verified hash' % index)
        if assume_verified or payload.signature_valid or vh == h:
            self._set_verified(index, h)
        self._expire_old_state()

    def payloads_ready(self):
        bad = dict([ (index,p) for (index,p) in self._payloads.items() \
                if self._verified_hashes.get(index, None) not in (None, p.hash()) ])
        for index in bad:
            print('ERROR: previously received payload %d does not match subsequently verified hash' % index)
        ready = dict([ (index,p) for (index,p) in self._payloads.items() \
                if self._verified_hashes.get(index, None) == p.hash() ])
        self._payloads = dict([ (index,p) for (index,p) in self._payloads.items() \
                if index not in ready and index not in bad ])
        for (index,p) in sorted(ready.items()):
            yield p

    def _extend_verification(self, payload):
        hlist = payload.auth_tag.chained_hashes
        for src_index, ch in hlist:
            if ch and src_index not in self._verified_hashes:
                self._set_verified(src_index, ch)

    def _set_verified(self, index, hash_value):
        self._verified_hashes[index] = hash_value
        if index > self._latest_verified_index:
            self._latest_verified_index = index
        if index in self._payloads:
            if hash_value == self._payloads[index].hash():
                self._extend_verification(self._payloads[index])
            else:
                print('ERROR: previously received payload %d does not match newly verified hash' % index)

    def _expire_old_state(self):
        for index_dict in (self._payloads, self._verified_hashes):
            delkeys = filter(lambda x: \
                    x < self._latest_verified_index - self._pre_lv_window \
                    or x > self._latest_verified_index + self._post_lv_window, \
                    index_dict.keys())
            for index in list(delkeys):
                index_dict.pop(index, None)
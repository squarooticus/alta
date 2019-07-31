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

from alta.model_payload import ModelPayload

from binascii import hexlify

p0 = ModelPayload.new_by_index(0)
p0.app_data = b'p0'
p1 = ModelPayload.new_by_index(1)
p1.app_data = b'p1'
p2 = ModelPayload.new_by_index(2)
p2.app_data = b'p2'
p0.auth_tag.chain_payload_hash(p1.index, p1.hash())
p2.auth_tag.chain_payload_hash(p0.index, p0.hash())
p2.auth_tag.chain_payload_hash(p1.index, p1.hash())
print('p0: %s' % hexlify(p0.hash()))
print('p1: %s' % hexlify(p1.hash()))
print('p2: %s' % hexlify(p2.hash()))

p2str = p2.to_str()
print('p2str: %s (%d) %s' % (hexlify(p2str), len(p2str), p2str))
c2, used = ModelPayload.from_str(p2str)
c2str = c2.to_str()
print('c2str: %s (%d) %s' % (hexlify(c2str), len(c2str), c2str))
print('c2: %s (%d used)' % (hexlify(c2.hash()), used))

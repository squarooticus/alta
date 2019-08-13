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

import sys
from alta.augmented_scheme import AugmentedScheme
from alta.model_payload import ModelPayload
from alta.producer import Producer
from alta.consumer import ConsumerEO
from alta.signature import Ed25519SigningKey
from binascii import hexlify

# Generate an Ed25519 key pair
skey = Ed25519SigningKey.generate()
vkey = skey.verify_key

# Construct the scheme, producer, and consumer
PayloadType = ModelPayload
a = 3
p = 5
s = AugmentedScheme(a,p)
ps = Producer(scheme=s)
cs = ConsumerEO(pre_lv_window=128, post_lv_window=128)

loss_pct = 5
loss_burst_max = p
signature_stride = a*p
seq_length = 151

def _test_payload(payload):
    return b'%04d %s' % (payload.index, b'.' * (1472-5-payload.auth_tag.max_len(s)))

last_index = seq_length - 1
inp_seq = [ PayloadType.new_by_index(index=i, signature_key=skey if i == last_index or (i % signature_stride) == 0 else None) for i in range(0,seq_length) ] + [ None ]
for p in inp_seq:
    if p is not None:
        p.app_data = _test_payload(p)

sent = 0
received = 0
delivered = 0

left_to_drop = 0

from random import randint

def _src_indices(payload):
    index = payload.index
    return ','.join([ str(x) for x in s.sources(index, 0, last_index)])

for i,src_payload in enumerate(inp_seq):
    if src_payload:
        ps.push_payload(src_payload)
        sent += 1
    else:
        ps.shutdown()

    for send_payload in ps.payloads_ready():
        print('s iter %d idx %d %s %s %d/%d %s %s' % (i, send_payload.index, hexlify(send_payload.hash()), send_payload.app_data[0:8], len(send_payload.app_data), len(send_payload.to_str()), ' VERIFIED' if send_payload.auth_tag.signature_key else '', _src_indices(send_payload)))
        drop = left_to_drop > 0 or randint(1,100) <= loss_pct
        if drop:
            if left_to_drop > 0:
                left_to_drop -= 1
            else:
                left_to_drop = randint(1,loss_burst_max-1)
            print('- %d' % (send_payload.index))
        else:
            recv_payload, used = PayloadType.from_str(send_payload.to_str(), signature_key=vkey)
            cs.push_payload(recv_payload)
            print('r iter %d idx %d %s %s %d/%d %s' % (i, recv_payload.index, hexlify(recv_payload.hash()), recv_payload.app_data[0:8], len(recv_payload.app_data), len(recv_payload.to_str()), ' VERIFIED' if recv_payload.signature_valid else ''))
            received += 1
        for recv_payload in cs.payloads_ready():
            delivered += 1
            print('d iter %d idx %d %s' % (i, recv_payload.index, hexlify(recv_payload.hash())))

print('\nsent: %d  received: %d  delivered: %d' % (sent, received, delivered))

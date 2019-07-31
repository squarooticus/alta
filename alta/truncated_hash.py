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

from binascii import hexlify

def TruncatedHash(hash_ctor, trunc_bytes):
    def __init__(self, *args, **kwargs):
        self._hstate = hash_ctor(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._hstate, name)

    def hexdigest(self):
        return hexlify(self.digest())

    def digest(self):
        return self._hstate.digest()[0:trunc_bytes]

    return type('Truncated%s' % hash_ctor.__name__.capitalize(), (), dict( __init__=__init__, __getattr__=__getattr__, digest=digest, hexdigest=hexdigest, hash_size=trunc_bytes ))

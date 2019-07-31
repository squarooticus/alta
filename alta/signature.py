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

import nacl.signing

def SignatureKeyTypes(skey_type, vkey_type, signature_len):
    skey_wrapper_type = None
    vkey_wrapper_type = None

    def mk_init(key_type):
        def __init__(self, *args, **kwargs):
            if '_import' in kwargs:
                self._key = kwargs['_import']
            else:
                self._key = key_type(*args, **kwargs)
        return __init__

    def __getattr__(self, name):
        return getattr(self._key, name)

    @property
    def verify_key(self):
        return vkey_wrapper_type(_import=self._key.verify_key)

    def generate(*args, **kwargs):
        return skey_wrapper_type(_import=skey_type.generate(*args, **kwargs))

    skey_wrapper_type = type(skey_type.__name__, (), dict( __init__=mk_init(skey_type), __getattr__=__getattr__, generate=generate, verify_key=verify_key, signature_len=signature_len ))
    vkey_wrapper_type = type(vkey_type.__name__, (), dict( __init__=mk_init(vkey_type), __getattr__=__getattr__, signature_len=signature_len ))

    return skey_wrapper_type, vkey_wrapper_type

Ed25519SigningKey, Ed25519VerifyKey = SignatureKeyTypes(nacl.signing.SigningKey, nacl.signing.VerifyKey, 64)

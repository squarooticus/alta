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

"""This module provides an implementation of the model payload as described in
the ALTA draft. This model payload employs single-octet explicit offsets
(supporting scheme-oblivious consumers), SHA-256 hashes truncated to 8 octets,
and an explicit 32-bit index in the authentication tag.

The application data is stored as a string instance attribute.

The scheme is determined by the publisher, while the signature algorithm is a
function of the signature key used to create the authentication tag.
"""

from .auth_tag import AuthTagEO
from .payload import Payload
from .truncated_hash import TruncatedHash

import hashlib
from functools import lru_cache

TruncatedSHA256 = TruncatedHash(hashlib.sha256, trunc_octets=8)

class ModelAuthTag(AuthTagEO):
    """The model authentication tag, employing single-octet explicit offsets,
    SHA-256 hashes truncated to 8 octets, and an explicit 32-bit index.
    """
    def __init__(self, index=None, signature_key=None, *args, **kwargs):
        """Initialize the model authentication tag.

        Keyword arguments:
        index -- The payload index (default None)
        signature_key -- The signing or verification key (default None)

        See ancestor classes for further arguments.
        """
        super().__init__(hash_cls=TruncatedSHA256, signature_key=signature_key, explicit_index_fmt='>I', *args, **kwargs)
        self._index = index

    @property
    def index(self):
        """Return the payload index."""
        return self._index

    @index.setter
    def index(self, value):
        """Set the payload index to the given value."""
        self._index = value

class ModelPayload(Payload):
    """The model payload, employing the ModelAuthTag."""
    def __init__(self, auth_tag):
        """Initialize the model payload.

        Keyword arguments:
        auth_tag -- The authentication tag for the enclosing payload.
        """
        self._auth_tag = auth_tag
        self._app_data = b''
        self._signature_valid = None

    @property
    def app_data(self):
        """Return the application data."""
        return self._app_data

    @app_data.setter
    def app_data(self, value):
        """Set the application data to the given value."""
        self._app_data = value

    @property
    def auth_tag(self):
        """Return the enclosed authentication tag."""
        return self._auth_tag

    @lru_cache(maxsize=100)
    def hash(self):
        """Compute and return the hash of this payload."""
        m = self.auth_tag.hash_cls()
        m.update(self.to_str())
        return m.digest()

    @property
    def index(self):
        """Return the payload index as specified in the enclosed authentication
        tag.
        """
        return self.auth_tag.index

    @property
    def signature_valid(self):
        """True iff a signature is present and valid."""
        return self._signature_valid

    @lru_cache(maxsize=100)
    def to_str(self):
        """Serialize the payload. If the authentication tag indicates the
        payload is to be signed, sign the result. Return the serialized
        payload."""
        pre_sig = b'%s%s' % (self.auth_tag.to_str(), self._app_data)
        if self.auth_tag.options.signature_present:
            return self.auth_tag.sign(pre_sig)
        else:
            return pre_sig

    @classmethod
    def from_str(cls, value, signature_key=None):
        """Deserialize a serialized ModelPayload into a new instance. Verify
        the signature if present. (signature_key.verify must throw if signature
        verification fails.)
        """
        auth_tag, used = ModelAuthTag.from_str(value, signature_key=signature_key)
        if auth_tag.options.signature_present:
            auth_tag.verify(value)
        pl = ModelPayload(auth_tag)
        if auth_tag.options.signature_present:
            pl._signature_valid = True
        pl.app_data = value[used:]
        return pl, len(value)

    @classmethod
    def new_by_index(cls, index, signature_key=None):
        """Create a new instance with the given index and (if specified)
        signing key."""
        return ModelPayload(ModelAuthTag(index=index, signature_key=signature_key))

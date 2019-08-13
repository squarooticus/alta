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

"""This module provides an interface to construct, manipulate, serialize, and
deserialize ALTA authentication tags. It provides a """

from abc import ABCMeta, abstractmethod
from struct import pack, unpack_from, calcsize
from functools import lru_cache

class OverwriteHashError(RuntimeError): pass

class AuthTagOptions:
    """The ALTA authentication tag options octet."""
    def __init__(self, hash_count=0, signature_present=False):
        """Initialize the options with the given arguments."""
        self._hash_count = hash_count
        self._signature_present = signature_present

    @property
    def hash_count(self):
        """Return the count of hashes specified in the options octet, which
        must match the number of hashes in the enclosing authentication
        tag.
        """
        return self._hash_count

    @hash_count.setter
    def hash_count(self, value):
        """Set the count of hashes specified in the options octet, which must
        match the number of hashes in the enclosing authentication tag.
        """
        self._hash_count = value

    @property
    def signature_present(self):
        """True iff the options indicate a signature is present in the
        enclosing authentication tag."""
        return self._signature_present

    @signature_present.setter
    def signature_present(self, value):
        """Set to true iff there is a signature present in the enclosing
        authentication tag.
        """
        self._signature_present = value

    @property
    def max_len(self):
        """Return the maximum length in octets of the options octet."""
        return 1

    def to_str(self):
        """Serialize the options octet."""
        return pack('>B', (self.hash_count << 5) | (int(self.signature_present) << 4))

    @classmethod
    def from_str(cls, value):
        """Deserialize an options octet into a class instance."""
        opt_int, = unpack_from('>B', value)
        return cls(opt_int >> 5, (opt_int & 0x10) != 0), 1

class AuthTag(metaclass=ABCMeta):
    """The ALTA authentication tag interface and partial implementation."""
    def __init__(self, hash_cls, signature_key, options=None):
        """Initialize an authentication tag with the given parameters.

        If options are None, a new options instance is created with a zero hash
        count, and with signature_present iff a signature key is specified.

        Keyword arguments:
        hash_cls -- A duck-typed hash class with an interface matching the
            fixed-length hashes from module hashlib.
        signature_key -- A signing or verification key instance of a duck-typed
            class matching nacl.SigningKey or nacl.VerifyKey, but with an added
            instance attribute signature_len denoting the fixed length of the
            signature in octets.
        options -- An AuthTagOptions instance (default None).
        """
        if options is None:
            self._options = AuthTagOptions(signature_present=signature_key is not None)
        else:
            self._options = options
        self._hash_cls = hash_cls
        if not hasattr(hash_cls, 'hash_size'):
            tmp_hash = hash_cls()
            hash_cls.hash_size = len(tmp_hash.digest())
        self._signature = None
        self._signature_key = signature_key
        self._hashes = {}

    def chain_payload_hash(self, src_index, src_hash):
        """Add the given src_hash to the set of hashes in this authentication
        tag for the source given src_index.
        """
        if src_index in self._hashes:
            raise OverwriteHashError()
        self._hashes[src_index] = src_hash
        self._options.hash_count = self.hash_count

    @property
    def chained_hashes(self):
        """Generate a (source index, source hash) tuple for each chained hash
        in order of increasing source index.
        """
        for src_index in sorted(self._hashes.keys()):
            yield (src_index, self._hashes[src_index])

    def get_chained_hash(self, src_index):
        """Return the hash for a given source index, or None if that source's
        hash is not stored in this authentication tag.
        """
        return self._hashes.get(src_index)

    @property
    def hash_cls(self):
        """Return the hash class employed by this authentication tag."""
        return self._hash_cls

    @property
    def hash_count(self):
        """Return the number of hashes chained into this authentication tag."""
        return len(self._hashes)

    @property
    def hash_size(self):
        """Return the size of the hash employed by this authentication tag, in
        octets.
        """
        return self.hash_cls.hash_size

    @property
    def options(self):
        """Return the options octet class instance."""
        return self._options

    @options.setter
    def options(self, value):
        """Set the options octet class instance to the given value."""
        self._options = value

    @property
    def signature_key(self):
        """Return the signature key, if any."""
        return self._signature_key

    @property
    @abstractmethod
    def index(self):
        """Abstract method that must be defined to return the index for the
        enclosing payload."""
        pass

    @abstractmethod
    def max_len(self, scheme):
        """Abstract method that must be defined to return the maximum length of
        this authentication payload, in octets, for the given scheme and
        self.index.
        """
        pass

    @property
    def signature(self):
        """Return the payload signature, if any."""
        return self._signature

    @signature.setter
    def signature(self, value):
        """Set the payload signature to the given value."""
        self._signature = value

    def sign(self, unsigned_payload):
        """Sign the given unsigned serialized payload and overwrite the
        signature field within the unsigned payload with the resulting
        signature. Return the signed serialized payload.
        """
        if not self._signature:
            self._signature = self._signature_key.sign(unsigned_payload).signature
        return self.add_signature(unsigned_payload, self._signature)

    @abstractmethod
    def add_signature(self, unsigned_payload, signature):
        """Abstract method that must be defined to overwrite the signature
        field within the unsigned payload with the given signature.
        """
        pass

    def verify(self, signed_payload):
        """If a signature is present in the given serialized signed payload,
        verify it and throw an exception if signature verification fails. Do
        nothing if no signature is present. (signature_key.verify must throw if
        signature verification fails.)
        """
        if self._options.signature_present:
            stripped_payload = self.strip_signature(signed_payload)
            self._signature_key.verify(stripped_payload, self._signature)

    @abstractmethod
    def strip_signature(self, signed_payload):
        """Abstract method that must be defined to overwrite the signature
        field within the signed payload with zeroes.
        """
        pass

    @abstractmethod
    def to_str(self):
        """Abstract method that must be defined to serialize this
        authentication tag.
        """
        pass

class AuthTagEO(AuthTag):
    """The ALTA authentication tag interface and mostly-complete implementation
    extending AuthTag with explicit offsets and a complete serialization
    format.
    """
    def __init__(self, explicit_index_fmt, *args, **kwargs):
        """Initialize an instance with the given arguments.

        Keyword arguments:
        explicit_index_fmt -- The struct.pack format for the index.

        See ancestor classes for further arguments.
        """
        super().__init__(*args, **kwargs)
        self._explicit_index_fmt = explicit_index_fmt

    @property
    def explicit_index_fmt(self):
        """Return the explicit index format string."""
        return self._explicit_index_fmt

    def max_len(self, scheme):
        """Return the maximum length of this authentication tag for the given
        scheme and self.index.
        """
        return self.options.max_len + self._explicit_index_size() + (1 + self.hash_size) * len(scheme.sources(self.index)) + (int(self.options.signature_present) * self.signature_key.signature_len if self.signature_key else 0)

    def add_signature(self, unsigned_payload, signature):
        """Overwrite the signature range in the given unsigned payload with
        the given signature.
        """
        return unsigned_payload[0:self._signature_ofs()] + signature + unsigned_payload[self._signature_ofs() + self.signature_key.signature_len:]

    def strip_signature(self, signed_payload):
        """Overwrite the signature range in the given payload with zeroes."""
        return signed_payload[0:self._signature_ofs()] + self._empty_signature() + signed_payload[self._signature_ofs() + self.signature_key.signature_len:]

    @lru_cache(maxsize=100)
    def to_str(self):
        """Serialize this authentication tag. If a signature is specified by
        options as present, the signature range is filled with zeroes, pending
        signing.
        """
        ret = self.options.to_str()
        if self._explicit_index_fmt:
            ret += pack(self._explicit_index_fmt, self.index)
        for (src_index, src_hash) in self.chained_hashes:
            ret += pack('>b%ds' % self.hash_size, src_index - self.index, src_hash)
        if self.options.signature_present:
            ret += self._empty_signature()
        return ret

    @classmethod
    def from_str(cls, value, *args, **kwargs):
        """Deserialize an authentication tag from the start of the given input.
        Return a tuple (new authentication tag instance, number of octets
        consumed).
        """
        options, used = AuthTagOptions.from_str(value)
        auth_tag = cls(options=options, *args, **kwargs)

        if auth_tag.explicit_index_fmt:
            auth_tag.index, = unpack_from(auth_tag.explicit_index_fmt, value, 1)
            used += auth_tag._explicit_index_size()

        fmt = '>' + ('b%ds' % (auth_tag.hash_size)) * auth_tag.options.hash_count
        ofs_hash_pairs = list(unpack_from(fmt, value, used))
        while ofs_hash_pairs:
            ofs = int(ofs_hash_pairs.pop(0))
            src_hash = ofs_hash_pairs.pop(0)
            auth_tag._hashes[ofs + auth_tag.index] = src_hash
        used += (1 + auth_tag.hash_size) * auth_tag.options.hash_count

        if auth_tag.options.signature_present:
            auth_tag.signature, = unpack_from('>%ds' % auth_tag.signature_key.signature_len, value, used)
            used += auth_tag.signature_key.signature_len

        return auth_tag, used

    def _empty_signature(self):
        """Return a signature field of all zeroes."""
        return b'\x00' * self.signature_key.signature_len

    def _explicit_index_size(self):
        """Return the size of the explicit index."""
        if self._explicit_index_fmt:
            return calcsize(self._explicit_index_fmt)
        else:
            return 0

    def _signature_ofs(self):
        """Return the offset into the serialized authentication tag of the
        signature field.
        """
        return self.options.max_len + self._explicit_index_size() + (1 + self.hash_size) * self.options.hash_count

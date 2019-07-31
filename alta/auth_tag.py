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

from abc import ABCMeta, abstractmethod
from struct import pack, unpack_from, calcsize
from functools import lru_cache

class OverwriteHashError(RuntimeError): pass

class AuthTagOptions:
    def __init__(self, hash_count=0, signature_present=False):
        self.hash_count = hash_count
        self.signature_present = signature_present

    @property
    def hash_count(self):
        return self._hash_count

    @hash_count.setter
    def hash_count(self, value):
        self._hash_count = value

    @property
    def signature_present(self):
        return self._signature_present

    @signature_present.setter
    def signature_present(self, value):
        self._signature_present = value

    @property
    def max_len(self):
        return 1

    def to_str(self):
        return pack('>B', (self.hash_count << 5) | (int(self.signature_present) << 4))

    @classmethod
    def from_str(cls, value):
        opt_int, = unpack_from('>B', value)
        return cls(opt_int >> 5, (opt_int & 0x10) != 0), 1

class AuthTag(metaclass=ABCMeta):
    def __init__(self, hash_cls, signature_key, options=None):
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
        if src_index in self._hashes:
            raise OverwriteHashError()
        self._hashes[src_index] = src_hash
        self._options.hash_count = self.hash_count

    @property
    def chained_hashes(self):
        for src_index in sorted(self._hashes.keys()):
            yield (src_index, self._hashes[src_index])

    def get_chained_hash(self, src_index):
        return self._hashes.get(src_index)

    @property
    def hash_cls(self):
        return self._hash_cls

    @property
    def hash_count(self):
        return len(self._hashes)

    @property
    def hash_size(self):
        return self.hash_cls.hash_size

    @property
    def options(self):
        return self._options

    @options.setter
    def options(self, value):
        self._options = value

    @property
    def signature_key(self):
        return self._signature_key

    def test(self):
        pass

    @property
    @abstractmethod
    def index(self):
        pass

    @abstractmethod
    def max_len(self, scheme):
        pass

    @property
    def signature(self):
        return self._signature

    @signature.setter
    def signature(self, value):
        self._signature = value

    def sign(self, unsigned_payload):
        if not self._signature:
            self._signature = self._signature_key.sign(unsigned_payload).signature
        return self.add_signature(unsigned_payload, self._signature)

    @abstractmethod
    def add_signature(self, unsigned_payload, signature):
        pass

    def verify(self, signed_payload):
        if self._options.signature_present:
            stripped_payload = self.strip_signature(signed_payload)
            self._signature_key.verify(stripped_payload, self._signature)

    @abstractmethod
    def strip_signature(self, signed_payload):
        pass

    @abstractmethod
    def to_str(self):
        pass

class AuthTagEO(AuthTag):
    def __init__(self, explicit_index='>I', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._explicit_index = explicit_index

    @property
    def explicit_index(self):
        return self._explicit_index

    def max_len(self, scheme):
        return self.options.max_len + self._explicit_index_size() + (1 + self.hash_size) * len(scheme.sources(self.index)) + (int(self.options.signature_present) * self.signature_key.signature_len if self.signature_key else 0)

    def add_signature(self, unsigned_payload, signature):
        return unsigned_payload[0:self._signature_ofs()] + signature + unsigned_payload[self._signature_ofs() + self.signature_key.signature_len:]

    def strip_signature(self, signed_payload):
        return signed_payload[0:self._signature_ofs()] + self._empty_signature() + signed_payload[self._signature_ofs() + self.signature_key.signature_len:]

    @lru_cache(maxsize=100)
    def to_str(self):
        ret = self.options.to_str()
        if self._explicit_index:
            ret += pack(self._explicit_index, self.index)
        for (src_index, src_hash) in self.chained_hashes:
            ret += pack('>b%ds' % self.hash_size, src_index - self.index, src_hash)
        if self.options.signature_present:
            ret += self._empty_signature()
        return ret

    @classmethod
    def from_str(cls, value, *args, **kwargs):
        options, used = AuthTagOptions.from_str(value)
        auth_tag = cls(options=options, *args, **kwargs)

        if auth_tag.explicit_index:
            auth_tag.index, = unpack_from(auth_tag.explicit_index, value, 1)
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
        return b'\x00' * self.signature_key.signature_len

    def _explicit_index_size(self):
        if self._explicit_index:
            return calcsize(self._explicit_index)
        else:
            return 0

    def _signature_ofs(self):
        return self.options.max_len + self._explicit_index_size() + (1 + self.hash_size) * self.options.hash_count

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

"""Abstract interface to ALTA payloads."""

from abc import ABCMeta, abstractmethod

class Payload(metaclass=ABCMeta):
    """Derive (or duck-type) to define a payload class."""
    @abstractmethod
    def hash(self):
        """Abstract method that must be defined to return the hash of the
        serialized payload.
        """
        pass

    @property
    @abstractmethod
    def index(self):
        """Abstract method that must be defined to return the index of the
        payload.
        """
        pass

    @property
    @abstractmethod
    def auth_tag(self):
        """Abstract method that must be defined to return the authentication
        tag for the payload.
        """
        pass

    @property
    @abstractmethod
    def signature_valid(self):
        """Abstract method that must be defined as true iff the signature in
        the given payload (if any) is valid.
        """
        pass

    @abstractmethod
    def to_str(self):
        """Abstract method that must be defined to serialize the payload."""
        pass

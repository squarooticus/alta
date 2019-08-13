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

"""This module provides an abstract interface to the scheme as defined in
Golle/Modadugu (2001).
"""

from abc import ABCMeta, abstractmethod

class Scheme(metaclass=ABCMeta):
    """A scheme for defining a DAG of payload hashes."""
    @abstractmethod
    def sources(self, seqno, start=None, end=None):
        """An abstract method that must be defined to return the list of
        indices of nodes from which hashes must be drawn for insertion into the
        given node's authentication tag. If first or last is specified,
        eliminate any node indices outside of that range.
        """
        pass

    @abstractmethod
    def destinations(self, seqno, start=None, end=None):
        """An abstract method that must be defined to return the list of
        indices of nodes into which a given node's hash must be placed. If
        first or last is specified, eliminate any node indices outside of that
        range.
        """
        pass

    @abstractmethod
    def is_ready(self, want_send_seqno, latest_seqno):
        """An abstract method that must be defined to be true if all payload
        hashes required to fully construct the payload with index
        want_send_idex must be available. Note that this requires payloads to
        be constructed in-order.
        """
        pass

    @abstractmethod
    def in_write_window(self, query_seqno, latest_seqno):
        """An abstract method that must be defined to be true if the hash of
        the payload with the given query_index may still be required to
        construct payloads from latest_index onward. Note that this requires
        payloads to be constructed in-order.
        """
        pass

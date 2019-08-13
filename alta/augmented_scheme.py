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

"""This module provides an implementation of the augmented scheme construction
according to Golle/Modadugu (2001):

https://www.semanticscholar.org/paper/Authenticating-Streamed-Data-in-the-Presence-of-Golle-Modadugu/169dbc1bd006a1d4b92ffcf379b6d1028dbdb5b6
"""

from .scheme import Scheme

# FIXME: This stuff needs to deal with rollover
class AugmentedPeriod:
    """The augmented period."""
    def __init__(self):
        """Initialize to a two-node graph."""
        A = { 'edges': [], 'pred': None }
        self.B = { 'edges': [], 'pred': A }
        self.next_insert = self.B
        self.nodect = 2

    def augment(self):
        """Augment the interval by inserting a pair of new nodes into the graph."""
        n1 = { 'edges': [ self.next_insert['pred'], self.next_insert ], 'pred': self.next_insert['pred'] }
        n2 = { 'edges': [ n1, self.next_insert ], 'pred': n1 }
        self.next_insert['pred'] = n2
        self.next_insert = n2
        self.nodect += 2

    def _flatten(self):
        """Flatten the graph into a list."""
        n = self.B
        idx = self.nodect - 1
        self.seq = []
        while n is not None:
            n['idx'] = idx
            self.seq.insert(0, n)
            idx -= 1
            n = n['pred']

    def doffsets(self):
        """Return the relative index offsets for the destination of each edge in the graph."""
        self._flatten()
        for n in self.seq[1:len(self.seq)-1]:
            yield sorted([ d['idx'] - n['idx'] for d in n['edges'] ])
        return

class AugmentedScheme(Scheme):
    """The augmented scheme for packet hash source/destination offsets."""
    def __init__(self, a, p=1):
        """Compute the offsets according to the specified arguments a and p, as
        specified in the source paper.
        """
        self.a = a # strength
        self.p = p # period
        self._construct_doffsets()
        self._compute_soffsets()

    def _construct_doffsets(self):
        """Compute destination offsets as specified in the paper."""
        # This doesn't get done often, so no sense making it hard to follow.
        # This follows the construction presented in the paper very closely.
        self.doffsets = []
        if self.p == 1:
            self.doffsets.append([1, self.a])
        elif self.p == 2:
            self.doffsets.append([2, 2*self.a])
            self.doffsets.append([-1, 1])
        elif self.p >= 3 and self.p % 2 == 1:
            ap = AugmentedPeriod()
            for i in range((self.p - 1) // 2):
                ap.augment()
            self.doffsets.append([self.p, self.p*self.a])
            self.doffsets.extend(ap.doffsets())
        else:
            raise ValueError()

    def _compute_soffsets(self):
        """Conceptually invert doffsets, resulting in the list of offsets to
        nodes whose hashes a given node needs to contain.
        """
        self.soffsets = [ [] for i in self.doffsets ]
        for idx,dofs in enumerate(self.doffsets):
            for o in dofs:
                self.soffsets[(idx + o) % self.p].append(-o)

    def sources(self, index, first=None, last=None):
        """Given a node index, return the list of indices of nodes from which
        hashes must be drawn. If first or last is specified, eliminate any node
        indices outside of that range.
        """
        return sorted([ index + o for o in self.soffsets[index % self.p]
            if (first is None or index+o >= first) and (last is None or index+o <= last) ])

    def destinations(self, index, first=None, last=None):
        """Given a node index, return the list of indices of nodes into which
        its hash must be placed. If first or last is specified, eliminate any node
        indices outside of that range.
        """
        return [ index + o for o in self.doffsets[index % self.p]
                if (first is None or index+o >= first) and (last is None or index+o <= last) ]

    def is_ready(self, want_send_index, latest_index):
        """True if all payload hashes required to fully construct the payload
        with index want_send_idex must be available. Note that this requires
        payloads to be constructed in-order.
        """
        return latest_index - want_send_index >= self.p-1

    def in_write_window(self, query_index, latest_index):
        """True if the hash of the payload with the given query_index may still
        be required to construct payloads from latest_index onward. Note that
        this requires payloads to be constructed in-order.
        """
        # FIXME: This should be true for only a+p-1 hashes at a time, not a*p
        return latest_index - query_index <= self.a * self.p

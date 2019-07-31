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

from .scheme import Scheme

# FIXME: This stuff needs to deal with rollover
class AugmentedPeriod:
    def __init__(self):
        A = { 'edges': [], 'pred': None }
        self.B = { 'edges': [], 'pred': A }
        self.next_insert = self.B
        self.nodect = 2

    def augment(self):
        n1 = { 'edges': [ self.next_insert['pred'], self.next_insert ], 'pred': self.next_insert['pred'] }
        n2 = { 'edges': [ n1, self.next_insert ], 'pred': n1 }
        self.next_insert['pred'] = n2
        self.next_insert = n2
        self.nodect += 2

    def _flatten(self):
        n = self.B
        idx = self.nodect - 1
        self.seq = []
        while n is not None:
            n['idx'] = idx
            self.seq.insert(0, n)
            idx -= 1
            n = n['pred']

    def doffsets(self):
        self._flatten()
        for n in self.seq[1:len(self.seq)-1]:
            yield sorted([ d['idx'] - n['idx'] for d in n['edges'] ])
        return

    def dump(self):
        self._flatten()
        for n in self.seq:
            print("%2d: %s" % (n['idx'], ' '.join([ '%d' % d['idx'] for d in n['edges'] ])))
            print("    %s" % (' '.join([ '%d' % (d['idx'] - n['idx']) for d in n['edges'] ])))
        print(list(self.doffsets()))

class AugmentedScheme(Scheme):
    def __init__(self, a, p=1):
        self.a = a # strength
        self.p = p # period
        self._construct_doffsets()
        self._compute_soffsets()

    def _construct_doffsets(self):
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
        # Conceptually inverts doffsets, resulting in the list of nodes whose
        # hashes a node needs to contain.
        self.soffsets = [ [] for i in self.doffsets ]
        for idx,dofs in enumerate(self.doffsets):
            for o in dofs:
                self.soffsets[(idx + o) % self.p].append(-o)

    def sources(self, index, first=None, last=None):
        return sorted([ index + o for o in self.soffsets[index % self.p]
            if (first is None or index+o >= first) and (last is None or index+o <= last) ])

    def destinations(self, index, first=None, last=None):
        return [ index + o for o in self.doffsets[index % self.p]
                if (first is None or index+o >= first) and (last is None or index+o <= last) ]

    def is_ready(self, want_send_index, latest_index):
        return latest_index - want_send_index >= self.p-1

    def in_write_window(self, query_index, latest_index):
        # FIXME: This should be true for only a+p-1 hashes at a time, not a*p
        return latest_index - query_index <= self.a * self.p

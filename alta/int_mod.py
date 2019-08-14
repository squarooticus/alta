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

from functools import total_ordering

@total_ordering
def IntMod(mod):
    def __init__(self, value):
        self._value = int(value % mod)

    def __add__(self, other):
        self._typecheck(other)
        return type(self)(self._value + int(other))

    def __sub__(self, other):
        self._typecheck(other)
        return type(self)(self._value - int(other))

    def __lt__(self, other):
        self._typecheck(other)
        if (self.__int__() - int(other)) % mod >= 3 * mod / 4:
            return True
        elif (self.__int__() - int(other)) % mod <= mod / 4:
            return False
        else:
            raise OverflowError()

    def __eq__(self, other):
        self._typecheck(other)
        return self.__int__() == (int(other) % mod)

    def __int__(self):
        return self._value % mod

    def __getattr__(self, name):
        return getattr(self._value, name)

    def __str__(self):
        return (self._value % mod).__str__()

    def _typecheck(self, other):
        if not isinstance(other, int) and not isinstance(other, type(self)):
            raise TypeError()

    return total_ordering(type('IntMod%d' % mod, (), dict( __init__=__init__, __add__=__add__, __sub__=__sub__, __lt__=__lt__, __eq__=__eq__, __int__=__int__, __getattr__=__getattr__, __str__=__str__, _typecheck=_typecheck)))

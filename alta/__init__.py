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

"""Asymmetric Loss-Tolerant Authentication (ALTA) Reference Implementation

This package provides a scheme for efficient asymmetric (i.e., signature-based)
authentication of packetized application data over a lossy transport such as
UDP. Regularly-paced signatures are available to receivers as anchors for a
mostly backward-looking directed acyclic graph (DAG) of payload hashes,
constructed in such a way that a single signature can authenticate many
payloads even when a subset of those payloads are not received.

This software is based on work by Golle and Modadugu (2001). More information
can be found in the internet draft at:

https://datatracker.ietf.org/doc/draft-krose-mboned-alta/
"""

from .augmented_scheme import *
from .auth_tag import *
from .common import *
from .consumer import *
from .int_mod import *
from .model_payload import *
from .payload import *
from .producer import *
from .scheme import *
from .signature import *
from .truncated_hash import *

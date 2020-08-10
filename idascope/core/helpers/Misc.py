#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  Collection of possibly unrelated,
#  miscellaneous functions that are useful.
#
########################################################################
#
#  This file is part of IDAscope
#
#  IDAscope is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import operator


def lrange(num1, num2=None, step=1):
    """
    Allows iteration over arbitrary numbers instead of dword long numbers.
    Credits go to:
    http://stackoverflow.com/questions/2187135/range-and-xrange-for-13-digit-numbers-in-python
    http://stackoverflow.com/users/263162/ricardo-cardenes
    """
    op = operator.__lt__

    if num2 is None:
        num1, num2 = 0, num1
    if num2 < num1:
        if step > 0:
            num1 = num2
        op = operator.__gt__
    elif step < 0:
        num1 = num2

    while op(num1, num2):
        yield num1
        num1 += step


def cleanCountingSuffix(name):
    """
    IDA does not support multiple identical names, thus often a suffix like _0, _1 is used to signal identity.
    This function will check a name for presence of such a suffix and remove to allow easier post-processing.
    """
    if "_w" in name:
        try:
            int(name[2 + name.rindex("_w"):])
            return name[:name.rindex("_w")]
        except:
            return name
    if "_" in name:
        try:
            int(name[1 + name.rindex("_"):])
            return name[:name.rindex("_")]
        except:
            return name
    return name

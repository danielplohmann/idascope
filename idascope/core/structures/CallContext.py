#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
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


class CallContext():
    """
    This class is an information container for a call instruction, used by SemanticIdentifier.
    """

    def __init__(self):
        self.called_function_name = ""
        self.real_called_function_name = ""
        self.address_of_call = 0
        self.called_address = 0
        self.tag = ""
        self.parameter_contexts = []

    def __str__(self):
        """
        Convenience function.
        @return: a nice string representation for this object
        """
        return "0x%x -> 0x%x %s [%s]" % (self.address_of_call, self.called_address, self.called_function_name, self.tag)

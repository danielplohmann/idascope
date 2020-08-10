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

# operand types defined by IDA
# o_void  =      0  # No Operand
# o_reg  =       1  # General Register (al,ax,es,ds...)                reg
# o_mem  =       2  # Direct Memory Reference  (DATA)                  addr
# o_phrase  =    3  # Memory Ref [Base Reg + Index Reg]                phrase
# o_displ  =     4  # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
# o_imm  =       5  # Immediate Value                                  value
# o_far  =       6  # Immediate Far Address  (CODE)                    addr
# o_near  =      7  # Immediate Near Address (CODE)                    addr


class ParameterContext():
    """
    This class is an information container for parameters that are handed over during function calls.
    """

    def __init__(self):
        self.parameter_type = ""
        self.parameter_name = ""
        self.push_address = -1
        self.ida_operand_type = -1
        self.ida_operand_value = -1
        self.value = -1
        self.valid = True
        pass

    def getRenderedPushAddress(self):
        """
        Get the address of this parameter in hex string form.
        @return: the parameter address in hex string form or "unresolved" if it has not been assigned.
        """
        if self.push_address != -1:
            return "0x%x" % self.push_address
        else:
            return "unresolved"

    def getRenderedValue(self):
        """
        Get the value of this parameter in hex string form.
        @return: the value in hex string form or "unresolved" if it has not been assigned.
        """
        if self.value != -1:
            return "0x%x" % self.value
        else:
            return "unresolved"

    def __str__(self):
        """
        Convenience function.
        @return: a nice string representation for this object
        """
        return "0x%x - %s %s: %s (%d, %d)" % (self.push_address, self.parameter_type, self.parameter_name, \
            self.value, self.ida_operand_type, self.ida_operand_value)

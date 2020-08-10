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


class AritlogBasicBlock():
    """
    This class is an information container for the arithmetic / logic heuristic of the
    crypto identifier
    """

    def __init__(self, start_ea, end_ea):
        self.arith_log_instructions = [
        "aaa",
        "aad",
        "aam",
        "aas",
        "adc",
        "add",
        "and",
        "daa",
        "cdq"
        "das",
        "dec",
        "div",
        "imul",
        "inc",
        "neg",
        "not",
        "or",
        "rcl",
        "rcr",
        "rol",
        "ror",
        "sal",
        "salc",
        "sar",
        "sbb",
        "shl",
        "shld",
        "shr",
        "shrd",
        "sub",
        "test",
        "xadd",
        "xor",
        ]
        self.self_nullifying_instructions = ["xor", "sbb", "sub"]
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.is_contained_in_loop = False
        self.is_contained_in_trivial_loop = False
        self.num_instructions = 0
        self.num_log_arit_instructions = 0
        self.num_zeroing_instructions = 0
        self.num_calls_in_function = 0
        self.aritlog_rating = -1
        self.nonzeroing_aritlog_rating = -1

    def getAritlogRating(self, is_nonzeroing_rating=False):
        """
        Calculates and returns the rating for this basic block
        @param is_nonzeroing_rating: determines whether zeroing instructions like xor eax, eax
                                     shall be taken into account or not.
        @type: is_nonzeroing_rating: boolean
        @return: the rating for this basic block
        """
        try:
            if is_nonzeroing_rating:
                self.nonzeroing_aritlog_rating = 1.0 * (self.num_log_arit_instructions - \
                    self.num_zeroing_instructions) / self.num_instructions
                return self.nonzeroing_aritlog_rating
            else:
                self.aritlog_rating = 1.0 * self.num_log_arit_instructions / self.num_instructions
                return self.aritlog_rating
        except ZeroDivisionError:
            return 0

    def updateInstructionCount(self, instruction, has_identical_operands):
        """
        Update the instruction count for this basic block.
        @param instruction: The mnemonic for a instruction of this block, as returned by IDA's I{GetMnem()}'
        @type: instruction: str
        @param has_identical_operands: determines if this instruction has two identical operands. Important for
                                       deciding whether the instruction zeroes a register or not
        @type: has_identical_operands: boolean
        """
        if instruction in self.arith_log_instructions:
            self.num_log_arit_instructions += 1
            if instruction in self.self_nullifying_instructions and has_identical_operands:
                self.num_zeroing_instructions += 1
        self.num_instructions += 1

    def __str__(self):
        """
        Convenience function.
        @return: a nice string representation for this object
        """
        return "0x%x - 0x%x (%d), aritlog: %02.2f%% (%02.2f%%) [%s]" % (self.start_ea, self.end_ea, \
        self.num_instructions, self.aritlog_rating * 100.0, self.nonzeroing_aritlog_rating * 100.0,
        self.is_contained_in_loop and "loop" or "no loop")

    def __lt__(self, other):
        """
        Convenience function for ordering.
        @param other: another I{AritLogBasicBlock}
        @type other: I{AritLogBasicBlock}
        @return: less if rating is less than of the other
        """
        return self.aritlog_rating() < other.aritlog_rating()

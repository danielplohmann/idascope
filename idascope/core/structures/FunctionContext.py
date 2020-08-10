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


class FunctionContext():
    """
    This class is an information container for functions.
    """

    def __init__(self):
        self.function_name = ""
        self.has_dummy_name = False
        self.has_tags = False
        self.function_address = 0
        self.number_of_basic_blocks = 0
        self.number_of_instructions = 0
        self.number_of_xrefs_from = 0
        self.number_of_xrefs_to = 0
        self.xrefs_from = set()
        self.calls_from = set()
        self.call_contexts = []

    def getTags(self):
        """
        Get all semantic tags covered by this function.
        """
        tags = []
        for call_ctx in self.call_contexts:
            if call_ctx.tag != "" and call_ctx.tag not in tags:
                tags.append(call_ctx.tag)
        return tags

    def getGroups(self):
        """
        Get all semantic groups covered by this function.
        """
        groups = []
        for call_ctx in self.call_contexts:
            if call_ctx.group != "" and call_ctx.group not in groups:
                groups.append(call_ctx.group)
        return groups

    def getCountForField(self, query):
        if query[0] == "additional":
            return self.getCountForAdditional(query[1])
        if query[0] == "tag":
            return self.getCountForTag(query[1])
        if query[0] == "group":
            return self.getCountForGroup(query[1])

    def getCountForTag(self, tag):
        tag_count = 0
        for call_ctx in self.call_contexts:
            if call_ctx.tag == tag:
                tag_count += 1
        return tag_count

    def getCountForGroup(self, group):
        group_count = 0
        for call_ctx in self.call_contexts:
            if call_ctx.group == group:
                group_count += 1
        return group_count

    def getCountForAdditional(self, additional):
        if additional == "num_blocks":
            return self.number_of_basic_blocks
        elif additional == "num_ins":
            return self.number_of_instructions
        elif additional == "xrefs_out":
            return self.number_of_xrefs_from
        elif additional == "xrefs_in":
            return self.number_of_xrefs_to
        else:
            print("[!] FunctionContext.getCountForAdditional(): Invalid query -> {}".format(additional))
            return 0

    def getAllTaggedAddresses(self):
        """
        Helper function, returning information about semantic tags in this function.
        """
        tagged_addresses = {}
        for call_ctx in self.call_contexts:
            if call_ctx.tag != "":
                tagged_addresses[call_ctx.address_of_call] = call_ctx.tag
        return tagged_addresses

    def __str__(self):
        """
        Convenience function.
        @return: a nice string representation for this object
        """
        return "0x%x %s [%d ins, %d blocks, %d calls, xrefs in/out: %d/%d]" % (self.function_address, \
            self.function_name, self.number_of_instructions, self.number_of_basic_blocks, len(self.call_contexts), \
            self.number_of_xrefs_to, self.number_of_xrefs_from)

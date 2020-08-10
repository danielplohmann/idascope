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


class FunctionContextFilter():
    """
    This class is defines the filter properties applicable to a scan result in order to select gathered information
    more precisely.
    """

    def __init__(self):
        self.display_tags = True
        self.display_groups = False
        self.display_all = False
        # tags, groups, additionals are 3-tuples of the form: (id, heading, description)
        # tuples having an id starting with an underscore are not displayed in result tables.
        self.tags = []
        self.groups = []
        self.enabled_tags = []
        self.enabled_groups = []
        self.additionals = [("_dummy_only", "Dummy Names", "Dummy names only"), \
            ("_tagged_only", "Tagged only", "Tagged functions only"), \
            ("num_blocks", "Blocks", "Number of Basic Blocks"), \
            ("num_ins", "Ins", "Number of Instructions"), \
            ("xrefs_in", "Xrefs IN", "Incoming cross-references"), \
            ("xrefs_out", "Xrefs OUT", "Outgoing cross-references")]
        self.enabled_additionals = []

    def generateColumnHeadings(self):
        headings = []
        for additional in self.enabled_additionals:
            if not additional[0].startswith("_"):
                headings.append(additional[1])
        if self.display_tags:
            for tag in self.enabled_tags:
                headings.append(tag[1])
        if self.display_groups:
            for group in self.enabled_groups:
                headings.append(group[1])
        return headings

    def getQueryForHeading(self, heading):
        for tag in self.tags:
            if tag[1] == heading:
                return ("tag", tag[0])
        for group in self.groups:
            if group[1] == heading:
                return ("group", group[0])
        for additional in self.additionals:
            if additional[1] == heading:
                return ("additional", additional[0])

    def isDisplayTagOnly(self):
        return ("_tagged_only", "Tagged only", "Tagged functions only") in self.enabled_additionals

    def isDisplayDummyOnly(self):
        return ("_dummy_only", "Dummy Names", "Dummy names only") in self.enabled_additionals

    def __str__(self):
        return "Tags: %s, Groups: %s\nTags: %s\nEnabled: %s\nGroups: %s\nEnabled: %s" % \
            (self.display_tags, self.display_groups, \
            self.tags, \
            self.enabled_tags, \
            self.groups, \
            self.enabled_groups)

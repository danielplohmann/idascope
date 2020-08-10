#!/usr/bin/python
########################################################################
# Copyright (c) 2014
# Christopher Kannen <ckannen<at>uni-bonn<dot>de>
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
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
#
########################################################################

from YaraRule import YaraRule
from YaraStatusController import StatusController


class YaraRuleLoader(object):
    """ Yara Rule Loader class """

    def __init__(self):
        """ init Yara Rule Loader Object """
        self.YaraRule = YaraRule
        self.StatusController =  StatusController
        self.statusController = StatusController()

    def loadRulesFromFile(self, filename):
        """ load content of file (1) """
        content = ""
        # read file
        with open(filename, 'r') as f_input:
            content = f_input.read()
        #clean content
        content_cleaned = self._cleanContent(content)
        # split content in Yara Rules
        return self._splitYaraRules(content, content_cleaned, filename)

    def _cleanContent(self, content):
        """ clean content, replace comments by spaces, replace strings by underlines """
        # current status while going through content ("", "string", "comment_multiline", "comment_singleline")
        self.statusController.reset()
        # result
        result = ""
        # go through file and copy everything but comments and strings, instead write blanks or underlines
        skip_i = 0
        for i in xrange(len(content)):
            # skip character(s)
            if (skip_i > 0):
                skip_i -= 1
                continue

            ## find strings - text
            # find beginnig of string
            if self.statusController.controlStatus("", self.statusController.findKeyword(content, i, "\""), "string_text"):
                result += "\""
                continue
            # skip next character when finding the escape character \ inside string
            if self.statusController.controlStatus("string_text", self.statusController.findKeyword(content, i, "\\"), None):
                result += "__"
                skip_i = 1
                continue
            # find end of string
            if self.statusController.controlStatus("string_text", self.statusController.findKeyword(content, i, "\""), ""):
                result += "\""
                continue
            ## find strings - regex
            # find beginnig of string
            if self.statusController.controlStatus("", self.statusController.findKeyword(content, i, "/")
                    and not self.statusController.findKeyword(content, i, "//")  and not self.statusController.findKeyword(content, i, "/*"), "string_regex"):
                result += "/"
                continue
            # skip next character when finding the escape character \ inside string
            if self.statusController.controlStatus("string_regex", self.statusController.findKeyword(content, i, "\\"), None):
                result += "__"
                skip_i = 1
                continue
            # find end of string
            if self.statusController.controlStatus("string_regex", self.statusController.findKeyword(content, i, "/"), ""):
                result += "/"
                continue

            ## find multi line comments
            # find beginnig of comment
            if self.statusController.controlStatus("", self.statusController.findKeyword(content, i, "/*"), "comment_multiline"):
                result += "  "
                skip_i = 1
                continue
            # find end of string
            if self.statusController.controlStatus("comment_multiline", self.statusController.findKeyword(content, i, "*/"), ""):
                result += "  "
                skip_i = 1
                continue

            ## find single line comments
            # find beginnig of comment
            if self.statusController.controlStatus("", self.statusController.findKeyword(content, i, "//"), "comment_singleline"):
                result += "  "
                skip_i = 1
                continue
            # find end of comment by finding end of line \r
            if self.statusController.controlStatus("comment_singleline", self.statusController.findKeyword(content, i, "\r"), ""):
                result += "\r"
                continue
            # find end of comment by finding end of line \n
            if self.statusController.controlStatus("comment_singleline", self.statusController.findKeyword(content, i, "\n"), ""):
                result += "\n"
                continue

            ## copy content
            # copy content if this is neither a comment nor a string, else add spaces or underlines
            if (self.statusController.status == ""):
                result += content[i]
            elif (self.statusController.status == "string_text"):
                result += "_"
            elif (self.statusController.status == "string_regex"):
                result += "_"
            else:
                result += " "

        # return content without comments and strings
        return result

    def _splitYaraRules(self, content, content_cleaned, filename):
        """ get all Yara rules split in sections (header, meta, strings, condition) """
        # result, list of Yara rules
        yara_rules = []
        # sections of current Yara rule
        current_rule = self.YaraRule(self)
        # status ("", "header", "meta", "strings", "condition"), file starts in Yara rule header, so status is "header"
        self.statusController.reset("header")
        # list of characters, one of them must stand in front of every section keyword
        needed_chars = [" ", "\r", "\n", "\t", "\"", "/", "{", "}"]

        # go through file and split it in Yara rules and them in sections
        for i in xrange(len(content_cleaned)):
            ## header
            # find end of header section
            if self.statusController.controlStatus("header", self.statusController.findKeyword(content_cleaned, i, "{"), ""):
                continue
            # copy header
            if (self.statusController.status == "header"):
                current_rule.raw_header += content[i]
                current_rule.raw_header_cleaned += content_cleaned[i]

            ## meta
            # find beginning of meta section
            self.statusController.controlStatus("", self.statusController.findKeyword(content_cleaned, i, "meta", needed_chars), "meta")
            # find end of meta section
            self.statusController.controlStatus("meta", self.statusController.findKeyword(content_cleaned, i, "strings", needed_chars), "")
            self.statusController.controlStatus("meta", self.statusController.findKeyword(content_cleaned, i, "condition", needed_chars), "")
            # copy meta
            if (self.statusController.status == "meta"):
                current_rule.raw_meta += content[i]
                current_rule.raw_meta_cleaned += content_cleaned[i]

            ## strings
            # find beginning of strings section
            self.statusController.controlStatus("", self.statusController.findKeyword(content_cleaned, i, "strings", needed_chars), "strings")
            # find end of strings section
            self.statusController.controlStatus("strings", self.statusController.findKeyword(content_cleaned, i, "condition", needed_chars), "")
            # copy meta
            if (self.statusController.status == "strings"):
                current_rule.raw_strings += content[i]
                current_rule.raw_strings_cleaned += content_cleaned[i]

            ## condition
            # find beginning of condition section
            self.statusController.controlStatus("", self.statusController.findKeyword(content_cleaned, i, "condition", needed_chars), "condition")
            # find end of condition section
            self.statusController.controlStatus("condition", self.statusController.findKeyword(content_cleaned, i, "}"), "endOfRule")
            # copy meta
            if (self.statusController.status == "condition"):
                current_rule.raw_condition += content[i]
                current_rule.raw_condition_cleaned += content_cleaned[i]

            ## find end of rule
            # save rule and reinit parsing
            if self.statusController.controlStatus("endOfRule", True, "header"):
                # add fully parsed rule to list and create next rule
                yara_rules.append(current_rule)
                # analyze Yara rule
                current_rule.filename = filename
                current_rule.analyze()
                current_rule = self.YaraRule(self)

        # return list of Yara rules
        return yara_rules

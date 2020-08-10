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

# from YaraStatusController import StatusController


class YaraRule(object):
    """ Yara Rule class """

    def __init__(self, parent):
        self.parent = parent
        self.statusController = parent.StatusController()
        self.filename = ""
        # set raw data of rule content, to be parsed by analyze* methods
        self.raw_header = ""
        self.raw_header_cleaned = ""
        self.raw_meta = ""
        self.raw_meta_cleaned = ""
        self.raw_strings = ""
        self.raw_strings_cleaned = ""
        self.raw_condition = ""
        self.raw_condition_cleaned = ""
        # rule header
        self.is_global = False
        self.is_private = False
        self.rule_name = ""
        self.rule_description = []
        # meta
        self.meta = []
        # strings
        self.strings = []
        #condition
        self.condition = ""
        # match data as provided by yara-python
        self.match_data = {}

    def checkRule(self):
        unique_names = {}
        for string in self.strings:
            if string[1] in unique_names:
                print "[!] Rule %s (%s) has duplicate variable name: \"%s\"" % (self.rule_name, self.filename, string[1])
                raise Exception("Duplicate variable name")
            else:
                unique_names[string[1]] = "loaded"
        return True

    def analyze(self):
        self._analyzeHeader()
        self._analyzeMeta()
        self._analyzeStrings()
        self._analyzeCondition()

    def _linebreakAndTabsToSpace(self, content):
        """ replace all linebreaks and tabs by spaces """
        new_content = ""
        for i in xrange(len(content)):
            if (content[i] == "\r"):
                new_content += " "
            elif (content[i] == "\n"):
                new_content += " "
            elif (content[i] == "\t"):
                new_content += " "
            else:
                new_content += content[i]
        return new_content

    def _analyzeHeader(self):
        """ analyze Yara rule header, find keywords PRIVATE and GLOBAL, get rule NAME and DESCRIPTION """
        self.statusController.reset()
        # delete tabs and linebreaks and then split rule header into single words
        raw_header_cleaned = self._linebreakAndTabsToSpace(self.raw_header_cleaned)
        raw_header_cleaned = raw_header_cleaned.replace(":", " : ")
        # analyze words
        for header_word in raw_header_cleaned.split(" "):
            if header_word == "private":
                self.is_private = True
            elif header_word == "global":
                self.is_global = True
            elif header_word == "rule":
                self.statusController.status = "find_rule_name"
            elif header_word == ":":
                self.statusController.status = "find_rule_description"
            elif self.statusController.status == "find_rule_name" and header_word != "":
                self.rule_name = header_word
            elif self.statusController.status == "find_rule_description" and header_word != "":
                self.rule_description.append(header_word)

    def _analyzeMeta(self):
        """ analyze meta section of Yara rule and save tuples (meta name, meta value) in list of meta entries """
        # current meta entry
        meta_name = ""
        meta_content = ""
        # status ("find_name", "name", "find_field_value", "value")
        self.statusController.reset("find_name")
        # read meta string and replace line breaks and tabs
        raw_meta = self.raw_meta
        raw_meta_cleaned = self._linebreakAndTabsToSpace(self.raw_meta_cleaned)
        # check if meta section exists
        if (len(raw_meta_cleaned) == 0) or (raw_meta_cleaned.find(":") == -1):
            return
        # insert an additional whitespace at the end as end delimiter to handle compact rules
        raw_meta += " "
        raw_meta_cleaned += " "
        # split at first colon
        temp, meta_body_cleaned = raw_meta_cleaned.split(":", 1)
        meta_body = raw_meta[len(temp) + 1:]
        # go through file and split it in Yara rules and them in sections
        for i in xrange(len(meta_body_cleaned)):
            # find beginning of meta entry name
            if self.statusController.controlStatus("find_name", not self.statusController.findKeyword(meta_body_cleaned, i, " "), "name"):
                pass
            # find end of meta entry name
            elif self.statusController.controlStatus("name", self.statusController.findKeyword(meta_body_cleaned, i, "="), "find_field_value"):
                continue
            # find beginning of meta entry value
            if self.statusController.controlStatus("find_field_value", not self.statusController.findKeyword(meta_body_cleaned, i, " "), "value"):
                # skip first letter by continue if value is a string
                if (meta_body_cleaned[i] == "\""):
                    continue
            # find end of meta entry value
            if self.statusController.controlStatus("value", i == len(meta_body_cleaned) - 1
                    or self.statusController.findKeyword(meta_body_cleaned, i, " ") or self.statusController.findKeyword(meta_body_cleaned, i, "\""), "find_name"):
                if not self.statusController.findKeyword(meta_body_cleaned, i, " ") and i == len(meta_body_cleaned) - 1:
                    meta_content += meta_body[i]
                if self.statusController.findKeyword(meta_body_cleaned, i, " ") or i == len(meta_body_cleaned) - 1:
                    if meta_content == "true":
                        meta_content = True
                    elif meta_content == "false":
                        meta_content = False
                    elif meta_content.isdigit():
                        meta_content = int(meta_content)
                meta_name = meta_name.strip()
                self.meta.append([meta_name, meta_content])
                # reset variables
                meta_name = ""
                meta_content = ""
                continue
            # copy content in meta name or meta value
            if (self.statusController.status == "name"):
                meta_name += meta_body[i]
            if (self.statusController.status == "value"):
                meta_content += meta_body[i]

    def _identifyStringType(self, indicator):
        """ identify type of string (text, regex, byte array) by it's first character """
        if indicator == "\"":
            return "text"
        if indicator == "/":
            return "regular_expression"
        if indicator == "{":
            return "byte_array"
        raise ValueError("Invalid string type indicator: %s" % indicator)

    def _checkStringValueTerminator(self, string_type, char):
        terminator_types = [("text", "\""), ("regular_expression", "/"), ("byte_array", "}")]
        return (string_type, char) in terminator_types

    def _analyzeStrings(self):
        """ analyze strings section of Yara rule and save tuples (string name, string value, string type) in list of string entries """
        # current string variable
        var_name = ""
        var_content = ""
        var_keywords = []
        # status ("find_name", "name", "find_field_value", "value")
        self.statusController.reset("find_name")

        # read strings string and replace line breaks and tabs
        raw_strings = self.raw_strings
        raw_strings_cleaned = self._linebreakAndTabsToSpace(self.raw_strings_cleaned)
        # check if meta section exists
        if ((len(raw_strings_cleaned) == 0) or (raw_strings_cleaned.find(":") == -1)):
            return
        # insert an additional whitespace at the end as end delimiter to handle compact rules
        raw_strings += " "
        raw_strings_cleaned += " "
        # split at first colon
        temp, raw_strings_cleaned = raw_strings_cleaned.split(":", 1)
        raw_strings = raw_strings[len(temp) + 1:]
        # go through file and split it in Yara rules and them in sections
        skip_i = 0
        for i in xrange(len(raw_strings_cleaned)):
            # skip character(s)
            if (skip_i > 0):
                skip_i -= 1
                continue
            # find beginning of string variable name
            if self.statusController.controlStatus("find_name", not self.statusController.findKeyword(raw_strings_cleaned, i, " "), "name"):
                pass
            # find end of string variable name
            elif self.statusController.controlStatus("name", self.statusController.findKeyword(raw_strings_cleaned, i, "="), "find_field_value"):
                continue
            # find beginning of string variable value
            if self.statusController.controlStatus("find_field_value", not self.statusController.findKeyword(raw_strings_cleaned, i, " "), "value"):
                string_variable_type = self._identifyStringType(raw_strings_cleaned[i])
                continue
            # find end of string variable value
            if (self.statusController.status == "value"):
                # check for all 3 types of strings (text, regex, byte array) if the string is complete
                # and save string variable if string is complete
                if self._checkStringValueTerminator(string_variable_type, raw_strings_cleaned[i]):
                    self.statusController.status = "stringModifier"
                    continue
            # look for string modification keywords after value ("wide", "ascii", "nocase", "fullword")
            string_modifiers = ["wide", "ascii", "nocase", "fullword"]
            for modifier in string_modifiers:
                if self.statusController.controlStatus("stringModifier", self.statusController.findKeyword(raw_strings_cleaned, i, modifier), "stringModifier"):
                    var_keywords.append(modifier)
                    skip_i = len(modifier)
                    break
            if (skip_i > 0):
                continue
            # check if there is any character after string, that is not part of a keyword and is no blank
            self.statusController.controlStatus("stringModifier", not self.statusController.findKeyword(raw_strings_cleaned, i, " "), "saveString")
            # save string if this the end of strings section is reached
            if i == len(raw_strings_cleaned) - 1:
                self.statusController.status = "saveString"
            # save string
            if (self.statusController.status == "saveString"):
                    # delete white spaces
                    var_name = var_name.strip()
                    if (string_variable_type == "regular_expression") or (string_variable_type == "byte_array"):
                        var_content = var_content.strip()
                    # save tuple in strings list
                    self.strings.append((string_variable_type, var_name, var_content, var_keywords))
                    # reset status
                    self.statusController.status = "name"
                    # reset variables
                    var_name = ""
                    var_content = ""
                    var_keywords = []
            # copy content in string name or string value
            if (self.statusController.status == "name"):
                var_name += raw_strings[i]
            if (self.statusController.status == "value"):
                var_content += raw_strings[i]

    def _analyzeCondition(self):
        """ analyze Yara rule condition """
        # delete tabs and linebreaks
        temp_condition = self._linebreakAndTabsToSpace(self.raw_condition_cleaned)
        # check if meta section exists
        if (len(temp_condition) == 0) or (temp_condition.find(":") == -1):
            return
        # split at first colon
        temp, temp_condition = temp_condition.split(":", 1)
        # delete white spaces at beginning and end of string
        temp_condition = temp_condition.strip()
        # replace multiple spaces in string
        temp_condition_len = 0
        while (temp_condition_len != len(temp_condition)):
            temp_condition_len = len(temp_condition)
            temp_condition = temp_condition.replace("  ", " ")
        # save condition in Yara rule
        self.condition = temp_condition

    def __str__(self):
        if not self.rule_name:
            return "Failed to load rule through YaraRuleLoader. Please be so kind and report this back for a bug fix! :)"
        start_delimiters = {"text": "\"", "regular_expression": "/ ", "byte_array": "{ "}
        end_delimiters = {"text": "\"", "regular_expression": " /", "byte_array": " }"}
        result = ""
        result += "global " if self.is_global else ""
        result += "private " if self.is_private else ""
        result += "rule " + self.rule_name
        if self.rule_description:
            result += " : " + " ".join(self.rule_description)
        result += "\n{\n"
        if self.meta:
            result += "    meta:\n"
            for meta_line in self.meta:
                if isinstance(meta_line[1], str):
                    result += " " * 8 + "%s = \"%s\"\n" % (meta_line[0], meta_line[1])
                else:
                    result += " " * 8 + "%s = %s\n" % (meta_line[0], meta_line[1])
            result += "\n"
        if self.strings:
            result += "    strings:\n"
            for string_line in self.strings:
                result += " " * 8 + "%s = %s%s%s %s\n" % (string_line[1],
                                                       start_delimiters[string_line[0]],
                                                       string_line[2],
                                                       end_delimiters[string_line[0]], " ".join(string_line[3]))
            result += "\n"
        result += "    condition:\n"
        result += " " * 8 + "%s\n" % self.condition
        result += "}"
        return result

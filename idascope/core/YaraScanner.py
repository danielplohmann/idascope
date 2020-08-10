#!/usr/bin/python
########################################################################
# Copyright (c) 2014
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
# Credits:
# * Christopher Kannen for contributing an independent loader for
#   YARA rules which allows to display unmatched rules and
#   content of rule files as loaded by yara-python
########################################################################

import os
import re
import time
import traceback

try:
    import yara
except ImportError:
    print("[-] ERROR: Could not import YARA (not installed?), scanner disabled.")
    yara = None

from IdaProxy import IdaProxy
import idascope.core.helpers.Misc as Misc
from idascope.core.helpers.YaraRuleLoader import YaraRuleLoader
from idascope.core.helpers.YaraRule import YaraRule
from idascope.core.helpers.YaraStatusController import StatusController


class YaraScanner():
    """
    A module to analyze and explore an IDB for semantics. For a set of API names, references to these
    are identified and used for creating context and allowing tagging of them.
    """

    def __init__(self, idascope_config):
        print ("[|] loading YaraScanner")
        self.os = os
        self.re = re
        self.traceback = traceback
        self.time = time
        self.yara = yara
        self.Misc = Misc
        self.StatusController = StatusController
        self.YaraRule = YaraRule
        self.ida_proxy = IdaProxy()
        self.yrl = YaraRuleLoader()
        # fields
        self.idascope_config = idascope_config
        self.num_files_loaded = 0
        self._compiled_rules = []
        self._yara_rules = []
        self._results = []
        self.segment_offsets = []

    def getResults(self):
        return self._results

    def load_rules(self):
        if not self.yara:
            return
        self.num_files_loaded = 0
        self._compiled_rules = []
        self._yara_rules = []
        for yara_path in self.idascope_config.yara_sig_folders:
            self._load_recursive(yara_path)

    def _load_recursive(self, yara_path):
        if self.os.path.isfile(yara_path):
            self._load_file(yara_path)
        elif self.os.path.isdir(yara_path):
            for dirpath, dirnames, filenames in self.os.walk(yara_path):
                for filename in sorted(filenames):
                    filepath = dirpath + self.os.sep + filename
                    self._load_file(filepath)

    def _load_file(self, filepath):
        try:
            rules_from_file = self.yrl.loadRulesFromFile(filepath)
            for rule in rules_from_file:
                rule.checkRule()
            self._yara_rules.extend(rules_from_file)
            rules = self.yara.compile(filepath)
            self._compiled_rules.append(rules)
            print "loading rules from file: %s (%d)" % (filepath, len(rules_from_file))
            if rules:
                self.num_files_loaded += 1
        except Exception as exc:
            print "[!] Could not load yara rules from file: %s --- Exception: " % filepath
            print ">" * 60
            print self.traceback.format_exc(exc)
            print "<" * 60

    def scan(self):
        if not self.yara:
            print "[!] yara-python not available, please install it from (http://plusvic.github.io/yara/)"
            return
        memory, offsets = self._get_memory()
        self.segment_offsets = offsets
        self._results = []
        matches = []
        print "[!] Performing YARA scan..."
        for rule in self._compiled_rules:
            matches.append(rule.match(data=memory, callback=self._result_callback))
        if len(matches) == 0:
            print "  [-] no matches. :("

    def _get_memory(self):
        result = ""
        segment_starts = [ea for ea in self.ida_proxy.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = self.ida_proxy.SegEnd(start)
            for ea in self.Misc.lrange(start, end):
                result += chr(self.ida_proxy.Byte(ea))
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return result, offsets

    def _result_callback(self, data):
        adjusted_offsets = []
        for string in data["strings"]:
            adjusted_offsets.append((self._translateMemOffsetToVirtualAddress(string[0]), string[1], string[2]))
        data["strings"] = adjusted_offsets
        if data["matches"]:
            print "  [+] YARA Match for signature: %s" % data["rule"]
        result_rule = None
        for rule in self._yara_rules:
            if rule.rule_name == data["rule"]:
                result_rule = rule
        if not result_rule:
            result_rule = self.YaraRule()
        result_rule.match_data = data
        self._results.append(result_rule)

        self.yara.CALLBACK_CONTINUE

    def _translateMemOffsetToVirtualAddress(self, offset):
        va_offset = 0
        for seg in self.segment_offsets:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset

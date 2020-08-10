#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Laura Guevara
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
# - Thanks to Branko Spasojevic for contributing a function for
#   finding and renaming potential wrapper functions.
########################################################################


class SemanticExplorer():
    """
    A module to analyze and explore an IDB for semantics. For a set of API names, references to these
    are identified and used for creating context and allowing tagging of them.
    """

    def __init__(self, parent):
        print ("[|] loading SemanticExplorer")
        self.parent = parent
        self.cc = parent.cc
        self.ida_proxy = self.cc.ida_proxy
        self.idascope_config = parent.config
        self.semantic_matches = []
        self.semantic_signatures = self.load_json(self.idascope_config.smtx_semantics_file)
        self.enums = self.load_json(self.idascope_config.smtx_enum_file)

        self.target_apis = self._collectSemanticApis(self.semantic_signatures)
        self.start_apis = self._collectStartApis(self.semantic_signatures)
        self.api_matcher = self.cc.ApiMatcher(self, self.target_apis, self.enums, self.idascope_config)

    def _loadDemoStub(self, idascope_config):
        """
        Load cached semantics for development
        """
        demo_path = self.cc.os.sep.join([idascope_config.root_file_path, "idascope", "data", "semantic_explorer", "example_result.json"])
        with open(demo_path, "r") as f_stub:
            results = self.cc.json.loads(f_stub.read())
        return results

    def _analyzeDemo(self):
        self.semantic_matches = self._loadDemoStub(self.idascope_config)

    def deduplicateMatches(self):
        deduplicated = {}
        for match in self.semantic_matches:
            key = ""
            addrs = []
            for api in match["hit"]["apis"]:
                if api["addr"] not in addrs:
                    addrs.append(api["addr"])
            key = ".".join(sorted(["0x%x" % addr for addr in addrs]))
            if not key in deduplicated:
                deduplicated[key] = match
        return deduplicated.values()

    def getSemanticMatches(self):
        matches = self.deduplicateMatches()
        return matches

    def getCategorizedMatches(self):
        matches = self.deduplicateMatches()
        categorized = {}
        for match in matches:
            category = match["category"]
            cat_list = categorized.get(category, [])
            cat_list.append(match)
            categorized[category] = cat_list
        return categorized

#####################################################################
# real

    def load_json(self, json_file):
        print "  loading json file: ", json_file
        loaded_dictionary = {}
        if self.cc.os.path.isfile(json_file):
            with open(json_file) as inf:
                content = inf.read()
                loaded_dictionary = self.cc.json.loads(content)
        else:
            Warning("Can't find file: %s!" % json_file)
        return loaded_dictionary

    def _collectSemanticApis(self, signatures):
        semantics = set()
        for semantic in signatures:
            for tags in semantic['api_sequence']:
                api = tags['api']
                semantics.add(api)
        return semantics

    def _collectStartApis(self, signatures):
        start_apis = set()
        for semantic in signatures:
            api = semantic['api_sequence'][0]['api']
            start_apis.add(api)
        return start_apis

    def analyze(self):
        # self._analyzeDemo()
        # return self.semantic_matches
        time_before = self.cc.time.time()
        print "\n  Building data structures..."
        self.buildDataStructure()
        print "  completed after %3.2f seconds.\n" % (self.cc.time.time() - time_before)

        print "\n   Matching Semantics..."
        self.semantic_matches = self.matchAll()
        print ("\n  Full analysis completed in %3.2f seconds.\n" % (self.cc.time.time() - time_before))
        return self.semantic_matches

    def buildDataStructure(self):
        self.func_blocks, self.func_calls, \
        self.block_calls, self.successors, self.predecessors, \
        self.semanticRefs = self.cc.ControlFlowBuilder(self, self.target_apis, self.start_apis).build()

    def matchAll(self):
        results = []
        for semantic in self.semantic_signatures:
            semantic_tag = semantic['tag']
            semantic_category = semantic['category'] if "category" in semantic else ""
            semantic_sequence = [(tag['api'], tag['parameters']) for tag in semantic['api_sequence']]
            apis = [api for api, parameter in semantic_sequence]

            for start_block in self.getAddressesWhereApiWasCalled(apis[0]):
                result = self._match(start_block, semantic_sequence)
                if result:
                    result_dict = {"tag": semantic_tag,
                                   "category": semantic_category,
                                   "hit": {"start_addr": 0x0,
                                           "apis": []
                                          }
                                  }
                    apis = []
                    for api_match in result:
                        api_dict = {"addr": int(api_match[0], 16), "api_name": api_match[1], "arguments": []}
                        arguments = []
                        for arg in api_match[2]:
                            arguments.append(arg)
                        api_dict["arguments"] = arguments
                        apis.append(api_dict)
                    result_dict["hit"]["apis"] = apis
                    result_dict["hit"]["start_addr"] = apis[0]["addr"]
                    results.append(result_dict)
        return results

    def _match(self, start, semantic_sequence):
        match = []
        semantic = self.cc.deque(semantic_sequence)
        api, parameters = semantic.popleft()

        next_blocks = self.cc.deque([start])
        visited = []

        while next_blocks:
            current = next_blocks.popleft()
            visited.append(current)
            block_matches, nested_functions = self.scanBlock(current, api, parameters)
            if block_matches:
                match.extend(block_matches)
                if semantic:
                    api, parameters = semantic.popleft()
                else:
                    return match
            for function in nested_functions:
                first_block = self.getFirstBlockOfFunction(function)
                jmp = self._isJump(function)
                if jmp:
                    next_blocks.append(jmp)
                else:
                    next_blocks.append(first_block)

            for block in self.successors.get(current, set()):
                if block not in visited:
                    next_blocks.append(block)
        return []

    def scanBlock(self, current, api, parameters):
        match = []
        nested_functions = []
        for call_name, call_addr in self.block_calls.get(current, []):
            semantic_call = api, parameters
            call = call_name, call_addr
            result = self.api_matcher.matchApiAndArguments(semantic_call, call)
            #call is to an API
            if result:
                match.append(result)
            #call is to a function
            else:
                nested_calls, nested_functions = self.scanNestedFunctions(api, call_name, nested_functions, parameters)
                if nested_calls:
                    match.extend(nested_calls)
        return match, nested_functions

    def getFirstBlockOfFunction(self, function):
        addr = self.ida_proxy.LocByName(function)
        block_addr = self.ida_proxy.FlowChart(self.ida_proxy.get_func(addr))
        if block_addr:
            block_addr = block_addr[0]
            block = block_addr.startEA, block_addr.endEA
            if block in self.func_blocks.get(block, set()):
                return block
        return self.findFirstBlockOfFunction(function, addr)

    def findFirstBlockOfFunction(self, function_name, function_ea):
        suspicious_blocks = self.func_blocks.get(function_name, set())
        for block_addr in self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_ea)):
            block = block_addr.startEA, block_addr.endEA
            if block in suspicious_blocks:
                return block
        return function_ea, function_ea

    def _isJump(self, function):
        calls = self.func_calls.get(function, set())
        if len(calls) == 1:
            call, addr = list(calls)[0]
            jmp = self.getFirstBlockOfFunction(call)
            return jmp
        return None

    def getAddressesWhereApiWasCalled(self, api):
        start_addr = set()
        for malwareApi in self.semanticRefs.keys():
            if api in malwareApi:
                start_addr = start_addr.union(self.semanticRefs[malwareApi])
        return start_addr

    def scanNestedFunctions(self, api, call_name, nested_functions, target_parameters):
        match = []
        semantic_call = api, target_parameters
        nested_calls = self.func_calls.get(call_name, set())
        if nested_calls:
            nested_functions.append(call_name)
            for call in nested_calls:
                result = self.api_matcher.matchApiAndArguments(semantic_call, call)
                if result:
                    match.append(result)
        return match, nested_functions

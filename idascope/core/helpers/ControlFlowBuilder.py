#!/usr/bin/python
########################################################################
# Copyright (c) 2014
# Laura Guevara <laura.guevara@fkie.fraunhofer.de>
# Daniel Plohmann (pnX) <daniel.plohmann@fkie.fraunhofer.de>
# All rights reserved.
########################################################################
#
#  This file is part of SemanticExplorer
#
#  SemanticExplorer is free software: you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
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


class ControlFlowBuilder():

    def __init__(self, parent, targetSemanticApis, start_apis):
        self.parent = parent
        self.cc = parent.cc
        self.ida_proxy = self.cc.ida_proxy
        self.func_blocks = {}
        self.predecessors = {}
        self.successors = {}
        self.start_apis = start_apis
        self.target_apis = targetSemanticApis
        self.manager = self.cc.ApiManager(self, self.target_apis)

    def build(self):
        semanticRefs = {}
        block_calls = {}
        function_apis = {}

        print "\n  Calculating control flow...",
        for function_ea in self.ida_proxy.Functions():
            function_name = self.ida_proxy.GetFunctionName(function_ea)

            #save basic blocks flow
            for block_addr in self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_ea)):
                block = block_addr.startEA, block_addr.endEA

                #save preds and succs
                self.predecessors[block] = self.predecessors.get(block, set())
                self.successors[block] = set((succ.startEA, succ.endEA) for succ in block_addr.succs())

                for succ in self.successors[block]:
                    self.predecessors[succ] = self.predecessors.get(succ, set())
                    self.predecessors[succ].add(block)

                suspicious_calls = self.manager._getSuspiciousBasicBlockCalls(block)
                if suspicious_calls:
                    block_calls[block] = suspicious_calls
                    function_apis[function_name] = function_apis.get(function_name, set()).union(suspicious_calls)
                    self.func_blocks[function_name] = self.func_blocks.get(function_name, set())
                    self.func_blocks[function_name].add(block)

                    #save addresses where each api has been call to later start first at apis from semantics
                    for api, addr in suspicious_calls:
                        #TODO currently, api can be anything, even not ascii which makes the check below fail
                        try:
                            api.decode("ascii")
                        except:
                            continue
                        for semantic_api in self.start_apis:
                            if semantic_api in api:
                                semanticRefs[api] = semanticRefs.get(api, set())
                                semanticRefs[api].add(block)

        print " done."
        print "  Pruning flow graph...",
        predecessors, successors = self.cc.ControlFlowFilter(self, self.func_blocks, self.predecessors, self.successors).filter()
        print " done."

        return self.func_blocks, function_apis, block_calls, successors, predecessors, semanticRefs


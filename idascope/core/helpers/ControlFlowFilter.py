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


class ControlFlowFilter():
    def __init__(self, parent, func_blocks, predecessors, successors):
        self.parent = parent
        self.cc = parent.cc
        self.ida_proxy = self.cc.ida_proxy
        self.func_blocks = func_blocks
        self.predecessors = predecessors
        self.successors = successors

    def filter(self):
        post = {}
        pre = {}
        for function_ea in self.ida_proxy.Functions():
            function = self.ida_proxy.GetFunctionName(function_ea)
            blocks = self.func_blocks.get(function, set())

            for addr in self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_ea)):
                block = addr.start_ea, addr.end_ea
                post[block] = post.get(block, set())
                pre[block] = pre.get(block, set())

                if block in blocks:
                    pre[block] = set(bb for bb in self.predecessors[block].union(pre.get(block, set())))
                    post[block] = set(bb for bb in self.successors[block].union(post.get(block, set())))
                else:
                    for parent in self.predecessors[block].union(pre.get(block, set())):
                        post[parent] = post.get(parent, set())
                        for succ in self.successors[block].union(post.get(block, set())):
                            post[parent].add(succ)

                    for child in self.successors[block].union(post.get(block, set())):
                        pre[child] = pre.get(child, set())
                        for pred in self.predecessors[block].union(pre.get(block, set())):
                            pre[child].add(pred)

            for start, end in blocks:
                block = start, end
                pre[block] = set(bb for bb in pre[block] if bb in blocks and bb != block)
                post[block] = set(bb for bb in post[block] if bb in blocks and bb != block)
        return pre, post

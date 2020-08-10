#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  Tests (=fixes) for bugs identified in IDAscope.
#
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

import sys
import unittest
import datetime
from test import *

from idascope.core.helpers.GraphHelper import GraphHelper
from idascope.core.structures.AritlogBasicBlock import AritlogBasicBlock


class IDAscope_Tests(unittest.TestCase):
    """
    Tests are created on demand when bugs are identified in order to document the source and solution to the problem.
    """

    def setUp(self):
        pass

    def test_assertionReminder(self):
        """
        A small reminder for myself because I frequently forgot some of the assertions used for testing...
        """
        # reachability
        assert True
        # comparison
        self.assertEquals("1", str(1))
        try:
            raise Exception("Exception text")
            # path exclution
            assert False
        except Exception as exc:
            # exceptions
            self.assertEquals(str(exc), "Exception text")

    def test_graphAlgorithms(self):
        """
        Date created: 2012-11-17
        In regard of issue: #4, https://bitbucket.org/daniel_plohmann/simplifire.idascope/issue/4/tarjan-algorithm-incorrect-results
        Description: A bug in the identification of looped blocks exists that will not spot blocks that are
                     contained in non-trivial and nested loops. Only blocks in trivial loops are spotted.
        """
        graph_helper = GraphHelper()

        graph_without_loops = {1: [2, 3], 2: [3], 3: [4]}
        scc_simple = graph_helper.calculateStronglyConnectedComponents(graph_without_loops)
        self.assertEquals([(4, ), (3, ), (2, ), (1, )], scc_simple)

        graph_with_trivial_loops = {1: [1, 2, 3], 2: [3], 3: [3, 4]}
        scc_trivial = graph_helper.calculateStronglyConnectedComponents(graph_with_trivial_loops)
        self.assertEquals([(4, ), (3, ), (2, ), (1, )], scc_trivial)

        graph_with_non_trivial_loops = {1: [2], 2: [3], 3: [1, 4], 4: [5]}
        scc_non_trivial = graph_helper.calculateStronglyConnectedComponents(graph_with_non_trivial_loops)
        self.assertEquals([(5, ), (4, ), (3, 2, 1)], scc_non_trivial)

        graph_with_non_and_trivial_loops = {1: [2], 2: [3], 3: [1, 4], 4: [4, 5]}
        scc_non_and_trivial = graph_helper.calculateStronglyConnectedComponents(graph_with_non_and_trivial_loops)
        self.assertEquals([(5, ), (4, ), (3, 2, 1)], scc_non_and_trivial)

        graph_with_nested_loops =  {1: [2], 2: [3], 3: [2, 4], 4: [1, 5], 5: [6]}
        scc_nested = graph_helper.calculateStronglyConnectedComponents(graph_with_nested_loops)
        self.assertEquals([(6, ), (5, ), (4, 3, 2, 1)], scc_nested)

        graph_example_issue_4 = {4368288: [4368265, 4368304], 4368322: [4368355, 4368322], 4368355: [], \
            4368263: [4368265], 4368265: [4368270], 4368270: [4368274, 4368283], 4368304: [4368311], \
            4368274: [4368285], 4368311: [4368322, 4368355], 4368283: [4368285], 4368285: [4368270, 4368288], \
            4368254: [4368263, 4368311]}
        scc_issue_4 = graph_helper.calculateStronglyConnectedComponents(graph_example_issue_4)
        self.assertEquals([(4368355,), (4368322,), (4368311,), (4368304,), \
            (4368283, 4368288, 4368285, 4368274, 4368270, 4368265), (4368263,), (4368254,)], scc_issue_4)

    def test_issue_4_scanAritlog(self):
        """
        Date created: 2012-11-17
        In regard of issue: #4, https://bitbucket.org/daniel_plohmann/simplifire.idascope/issue/4/tarjan-algorithm-incorrect-results
        Description: A bug in the identification of looped blocks exists that will not spot blocks that are
                     contained in non-trivial and nested loops. Only blocks in trivial loops are spotted.
                     This test contains an abstraction of the algorithm of CryptoIdentifer.scanAritlog()
                     intended to finding looped blocks.
        Expected result: 7 blocks in loops (nontrivial + trivial + nested)
        Actual result: 1 block in loop (trivial)
        """
        graph_example_issue_4 = {4368288: [4368265, 4368304], 4368322: [4368355, 4368322], 4368355: [], \
            4368263: [4368265], 4368265: [4368270], 4368270: [4368274, 4368283], 4368304: [4368311], \
            4368274: [4368285], 4368311: [4368322, 4368355], 4368283: [4368285], 4368285: [4368270, 4368288], \
            4368254: [4368263, 4368311]}
        # ABSTRACTED: Removed dependency on the concrete sample where this bug appeared.
        # ABSTRACTED: Necessity to loop over all functions in the sample
        aritlog_blocks = []
        function_blocks = []
        function_dgraph = {}
        blocks_in_loops = set()
        for current_block in graph_example_issue_4:
            block = AritlogBasicBlock(current_block, 0)
            # ABSTRACTED: enumeration of instructions to build Aritlog ratings.
            function_blocks.append(block)
            # prepare graph for Tarjan's algorithm
            succeeding_blocks = [succ for succ in graph_example_issue_4[current_block]]
            function_dgraph[current_block] = succeeding_blocks
            # add trivial loops
            if current_block in succeeding_blocks:
                blocks_in_loops.update([current_block])
        # perform Tarjan's algorithm to identify strongly connected components (= loops) in the function graph
        graph_helper = GraphHelper()
        strongly_connected = graph_helper.calculateStronglyConnectedComponents(function_dgraph)
        non_trivial_loops = [component for component in strongly_connected if len(component) > 1]
        # This part in the code prior to the bugfix contains the error.
        ###############################################
        # for component in non_trivial_loops:
        #     blocks_in_loops.update(non_trivial_loops)
        ###############################################
        # component is a tuple. In the above code blocks_in_loops will consist of tuples instead of the actual
        # blocks contained in the tuples, as is evaluated against later on.
        # FIX: introduce another loop to enumerate the tuples elements.
        for component in non_trivial_loops:
            for block in component:
                blocks_in_loops.update([block])
        for block in function_blocks:
            if block.start_ea in blocks_in_loops:
                block.is_contained_in_loop = True
        aritlog_blocks.extend(function_blocks)
        num_looped_blocks = len([block for block in aritlog_blocks if block.is_contained_in_loop])
        self.assertEquals(7, num_looped_blocks)


def main(argv):
    print "#" * 10 + " NEW TEST RUN: IDAscope ## " + datetime.datetime.utcnow().strftime("%A, %d. %B %Y %I:%M:%S") + " " + "##"
    unittest.main()


if __name__ == '__main__':
    sys.exit(main(sys.argv))

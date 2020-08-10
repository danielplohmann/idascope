#!/usr/bin/python

from idascope.core.IdaProxy import IdaProxy


class GraphHelper():

    def __init__(self, class_collection):
        self.ida_proxy = class_collection.ida_proxy

    def handleGraphRecursions(self, graph):
        """
        Analyze an arbitrary graph structure for strongly connected components. If such are found, break the
        loops and return the graph with an additional key "recursions" that can be used to indicate that these
        loops have been broken.
        @param graph: a dictionary describing a directed graph, with keys as nodes and values as successors.
        @type graph: (dict)
        @return: (dict) the modified graph with an additional key "recursions", indicating the broken recursions.
        """
        strongly_connected = self.calculateStronglyConnectedComponents(graph["nodes"])
        non_trivial_loops = [component for component in strongly_connected if len(component) > 1]
        if len(non_trivial_loops) > 0:
            print "here are loops: 0x%x >> %s" % \
                (graph["root"], ", ".join(["0x%x" % addr for addr in non_trivial_loops[0]]))
            self.renderGraph(graph)

    def renderGraph(self, graph):
        for function_addr in graph["nodes"].keys():
            refs = graph["nodes"][function_addr]
            print "0x%x (%s)" % (function_addr, self.ida_proxy.GetFunctionName(function_addr))
            for ref in refs:
                print "  > 0x%x (%s)" % (ref, self.ida_proxy.GetFunctionName(ref))

    def calcAvgOutDegree(self, graph):
        out_refs = 0
        for function_addr in graph["nodes"].keys():
            out_refs += len(graph["nodes"][function_addr])
        print "0x%x -> %2.2f edges per node" % (graph["root"], 1.0 * out_refs / len(graph["nodes"].keys()))

    def calculateStronglyConnectedComponents(self, graph):
        """
        Tarjan's Algorithm (named for its discoverer, Robert Tarjan) is a graph theory algorithm
        for finding the strongly connected components of a graph.
        This can be used to find loops.
        Based on: http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm

        Implementation by Dries Verdegem:
        http://www.logarithmic.net/pfh-files/blog/01208083168/tarjan.py
        Taken from Dr. Paul Harrison Blog:
        http://www.logarithmic.net/pfh/blog/01208083168

        @param graph: a dictionary describing a directed graph, with keys as nodes and values as successors.
        @type graph: (dict)
        @return: (a list of tuples) describing the SCCs
        """

        index_counter = [0]
        stack = []
        lowlinks = {}
        index = {}
        result = []

        def calculateSccForNode(node):
            # set the depth index for this node to the smallest unused index
            index[node] = index_counter[0]
            lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            # Consider successors of `node`
            try:
                successors = graph[node]
            except:
                successors = []
            for successor in successors:
                if successor not in lowlinks:
                    # Successor has not yet been visited; recurse on it
                    calculateSccForNode(successor)
                    lowlinks[node] = min(lowlinks[node], lowlinks[successor])
                elif successor in stack:
                    # the successor is in the stack and hence in the current strongly connected component (SCC)
                    lowlinks[node] = min(lowlinks[node], index[successor])
            # If `node` is a root node, pop the stack and generate an SCC
            if lowlinks[node] == index[node]:
                connected_component = []
                while True:
                    successor = stack.pop()
                    connected_component.append(successor)
                    if successor == node:
                        break
                component = tuple(connected_component)
                # storing the result
                result.append(component)
        for node in graph:
            if node not in lowlinks:
                calculateSccForNode(node)
        return result

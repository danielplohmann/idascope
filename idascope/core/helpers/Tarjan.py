#!/usr/bin/python
class Tarjan():
    """
    Tarjan's Algorithm (named for its discoverer, Robert Tarjan) is a graph theory algorithm
    for finding the strongly connected components of a graph.
    This can be used to find loops.
    Based on: http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm

    Implementation by Dries Verdegem:
    http://www.logarithmic.net/pfh-files/blog/01208083168/tarjan.py
    Taken from Dr. Paul Harrison Blog:
    http://www.logarithmic.net/pfh/blog/01208083168
    """

    def __init__(self):
        pass

    def calculate_strongly_connected_components(self, graph):
        """
        @param graph: a dictionary describing a directed graph, with keys as nodes and values as successors.
        @type graph: (dict)
        @return: (a list of tuples) describing the SCCs
        """

        index_counter = [0]
        stack = []
        lowlinks = {}
        index = {}
        result = []

        def calculate_scc_for_node(node):
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
                    calculate_scc_for_node(successor)
                    lowlinks[node] = min(lowlinks[node],lowlinks[successor])
                elif successor in stack:
                    # the successor is in the stack and hence in the current strongly connected component (SCC)
                    lowlinks[node] = min(lowlinks[node],index[successor])

            # If `node` is a root node, pop the stack and generate an SCC
            if lowlinks[node] == index[node]:
                connected_component = []

                while True:
                    successor = stack.pop()
                    connected_component.append(successor)
                    if successor == node: break
                component = tuple(connected_component)
                # storing the result
                result.append(component)

        for node in graph:
            if node not in lowlinks:
                calculate_scc_for_node(node)

        return result

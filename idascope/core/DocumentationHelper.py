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

import json

from IdaProxy import IdaProxy

from helpers import JsonHelper


    ## 6 nice opposing colors as used in IDAscope standard config
    ##
    ## Red:      0xFF3333 - 0xFFB3B3 -> Registry
    ## Violet:   0x7A24B4 - 0x9E7EB4 -> Execution
    ## Blue:     0x2779C1 - 0x87A6C1 -> Network
    ## Green:    0x32BD26 - 0x89BD84 -> Crypto
    ## Yellow:   0xFFFF33 - 0xFFFFB3 -> Memory Manipulation
    ## Orange:   0xFFA733 - 0xFFDFB3 -> Files
    ## Notice: IDA uses BBGGRR


class DocumentationHelper():
    """
    This class handles instruction coloring.
    """

    # data layout of color maps
    layout_color_map = {"tag": {"base_color": 0x112233, "highlight_color": 0x445566}}

    def __init__(self, idascope_config):
        print ("[|] loading DocumentationHelper")
        self.ida_proxy = IdaProxy()
        # default colors are grey / light red / red
        self.default_neutral_color = 0xCCCCCC
        self.default_base_color = 0xB3B3FF
        self.default_highlight_color = 0x3333FF
        self.color_state = "unknown"
        self.idascope_config = idascope_config
        self._loadConfig(self.idascope_config.inspection_tags_file)
        return

    def _loadConfig(self, config_filename):
        """
        Loads a semantic configuration file and generates a color map from the contained information.
        @param config_filename: filename of a semantic configuration file
        @type config_filename: str
        """
        config_file = open(config_filename, "r")
        config = config_file.read()
        parsed_config = json.loads(config, object_hook=JsonHelper.decode_dict)
        self.default_neutral_color = int(parsed_config["default_neutral_color"], 16)
        self.default_base_color = int(parsed_config["default_base_color"], 16)
        self.default_highlight_color = int(parsed_config["default_highlight_color"], 16)
        self.color_map = self._generateColorMapFromDefinitions(parsed_config)
        return

    def _generateColorMapFromDefinitions(self, config):
        """
        Internal function to generate a color map from a semantic definitions config file.
        @param definitions: the defintions part of a semantic definitions config file.
        @type definitions: dict
        @return: a dictionary of a color map, see I{layout_color_map} for a reference
        """
        color_map = {}
        for definition in config["semantic_definitions"]:
            # convert text representation of color codes to numbers
            group_colors = self._getColorsForGroup(definition["group"], config)
            color_map[definition["tag"]] = {"base_color": int(group_colors[0], 16), \
                "highlight_color": int(group_colors[1], 16)}
        return color_map

    def _getColorsForGroup(self, target_group, config):
        for group in config["semantic_groups"]:
            if group["tag"] == target_group:
                return (group["base_color"], group["highlight_color"])
        print "[-] Failed to get colors for group \"%s\" - you might want to check your semantics file." % target_group
        return (self.default_base_color, self.default_highlight_color)

    def uncolorAll(self):
        """
        Uncolors all instructions of all segments by changing their color to white.
        """
        for seg_ea in self.ida_proxy.Segments():
            for function_address in self.ida_proxy.Functions(self.ida_proxy.SegStart(seg_ea), \
                self.ida_proxy.SegEnd(seg_ea)):
                for block in self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_address)):
                    for head in self.ida_proxy.Heads(block.startEA, block.endEA):
                        self.colorInstruction(head, 0xFFFFFF, refresh=False)
        self.ida_proxy.refresh_idaview_anyway()

    def colorInstruction(self, address, color, refresh=True):
        """
        Colors the instruction at an address with the given color code.
        @param address: address of the instruction to color
        @type address: int
        @param color: color-code to set for the instruction
        @type color: int (0xBBGGRR)
        @param refresh: refresh IDA view to ensure the color shows directly, can be omitted for performance.
        @type refresh: boolean
        """
        self.ida_proxy.SetColor(address, self.ida_proxy.CIC_ITEM, color)
        if refresh:
            self.ida_proxy.refresh_idaview_anyway()

    def colorBasicBlock(self, address, color, refresh=True):
        """
        Colors the basic block containing a target address with the given color code.
        @param address: address an instruction in the basic block to color
        @type address: int
        @param color: color-code to set for the instruction
        @type color: int (0xBBGGRR)
        @param refresh: refresh IDA view to ensure the color shows directly, can be omitted for performance.
        @type refresh: boolean
        """
        function_chart = self.ida_proxy.FlowChart(self.ida_proxy.get_func(address))
        for block in function_chart:
            if block.startEA <= address < block.endEA:
                for head in self.ida_proxy.Heads(block.startEA, block.endEA):
                    self.colorInstruction(head, color, refresh)

    def getNextColorScheme(self):
        """
        get the next color scheme in the three-cycle "individual/mono/uncolored", where individual is semantic coloring
        @return: next state
        """
        if self.color_state == "individual":
            return "mono"
        elif self.color_state == "mono":
            return "uncolored"
        elif self.color_state == "uncolored":
            return "individual"
        else:
            return "individual"

    def selectHighlightColor(self, tag):
        """
        automatically chooses the highlight color for a tag based on the current color scheme
        @return: (int) a color code
        """
        if self.getNextColorScheme() == "uncolored":
            return 0xFFFFFF
        elif self.getNextColorScheme() == "mono":
            return self.default_highlight_color
        else:
            return self.color_map[tag]["highlight_color"]

    def selectBaseColor(self, tagged_addresses_in_block):
        """
        automatically chooses the base color for a block based on the current color scheme
        @param tagged_addresses_in_block: all tagged addresses in a basic block for which the color shall be chosen
        @type tagged_addresses_in_block: a list of tuples (int, str) containing pairs of instruction addresses and tags
        @return: (int) a color code
        """
        if self.getNextColorScheme() == "uncolored":
            return 0xFFFFFF
        elif self.getNextColorScheme() == "mono":
            return self.default_base_color
        else:
            tags_in_block = [item[1] for item in tagged_addresses_in_block]
            colors_in_block = set([self.color_map[tags_in_block[index]]["base_color"] \
                for index in xrange(len(tags_in_block))])
            if len(colors_in_block) == 1:
                return colors_in_block.pop()
            else:
                return self.default_neutral_color

    def colorize(self, scan_result):
        """
        perform coloring on the IDB, based on a scan performed by SemanticIdentifier
        @param scan_result: result of a scan as performed by SemanticIdentifier
        @type scan_result: a dictionary with key/value entries of the following form: (address, [FunctionContext])
        """
        for function_address in scan_result.keys():
            tagged_addresses_in_function = scan_result[function_address].getAllTaggedAddresses()
            function_chart = self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_address))
            for basic_block in function_chart:
                tagged_addresses_in_block = [(addr, tagged_addresses_in_function[addr]) for addr in \
                    tagged_addresses_in_function.keys() if addr in xrange(basic_block.startEA, basic_block.endEA)]
                if len(tagged_addresses_in_block) > 0:
                    base_color = self.selectBaseColor(tagged_addresses_in_block)
                    self.colorBasicBlock(basic_block.startEA, base_color, refresh=False)
                    for tagged_address in tagged_addresses_in_block:
                        highlight_color = self.selectHighlightColor(tagged_address[1])
                        self.colorInstruction(tagged_address[0], highlight_color, refresh=False)
        self.color_state = self.getNextColorScheme()
        self.ida_proxy.refresh_idaview_anyway()

    def getNextNonFuncInstruction(self, addr):
        next_instruction = addr
        while next_instruction != self.ida_proxy.BAD_ADDR:
            next_instruction = self.ida_proxy.find_not_func(next_instruction, self.ida_proxy.SEARCH_DOWN)
            flags = self.ida_proxy.GetFlags(next_instruction)
            if self.ida_proxy.isCode(flags):
                return next_instruction
        return self.ida_proxy.BAD_ADDR

    def convertNonFunctionCode(self):
        self.convertAnyProloguesToFunctions()
        # do a second run to define the rest
        next_instruction = self.ida_proxy.minEA()
        while next_instruction != self.ida_proxy.BAD_ADDR:
            next_instruction = self.getNextNonFuncInstruction(next_instruction)
            print("[+] Fixed undefined code to function @ [%08x]" % \
                (next_instruction))
            self.ida_proxy.MakeFunction(next_instruction)
        return

    def convertAnyProloguesToFunctions(self):
        self.convertDataWithPrologueToCode()
        self.convertNonFunctionCodeWithPrologues()

    def convertNonFunctionCodeWithPrologues(self):
        next_instruction = self.ida_proxy.minEA()
        while next_instruction != self.ida_proxy.BAD_ADDR:
            next_instruction = self.getNextNonFuncInstruction(next_instruction)
            if self.ida_proxy.GetMnem(next_instruction).startswith("push") and \
                self.ida_proxy.GetOpType(next_instruction, 0) == 1 and \
                self.ida_proxy.GetOperandValue(next_instruction, 0) == 5:
                instruction_after_push = self.getNextNonFuncInstruction(next_instruction)
                if self.ida_proxy.GetMnem(instruction_after_push).startswith("mov") and \
                    self.ida_proxy.GetOpType(instruction_after_push, 0) == 1 and \
                    self.ida_proxy.GetOperandValue(instruction_after_push, 0) == 5 and \
                    self.ida_proxy.GetOpType(instruction_after_push, 1) == 1 and \
                    self.ida_proxy.GetOperandValue(instruction_after_push, 1) == 4:
                        print("[+] Fixed undefined code with function prologue (push ebp; mov ebp, esp) to function " \
                            + "@ [%08x]" % (next_instruction))
                        self.ida_proxy.MakeFunction(next_instruction)

    def convertDataWithPrologueToCode(self):
        current_seg = self.ida_proxy.FirstSeg()
        seg_end = self.ida_proxy.SegEnd(current_seg)
        while current_seg != self.ida_proxy.BAD_ADDR:
            signature_hit = self.ida_proxy.find_binary(current_seg, seg_end, "55 8B EC", 16, 1)
            if signature_hit != self.ida_proxy.BAD_ADDR:
                flags = self.ida_proxy.GetFlags(signature_hit)
                if not self.ida_proxy.isCode(flags):
                    self.ida_proxy.MakeFunction(signature_hit)
                    print("[+] Fixed undefined data with potential function prologue (push ebp; mov ebp, esp) to function " \
                            + "@ [%08x]" % (signature_hit))
                current_seg = signature_hit + 3 + 1
            else:
                current_seg = self.ida_proxy.NextSeg(seg_end)
                if not current_seg == self.ida_proxy.BAD_ADDR:
                    seg_end = self.ida_proxy.SegEnd(current_seg)

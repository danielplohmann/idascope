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
# Credits:
# - Thanks to Branko Spasojevic for contributing a function for
#   finding and renaming potential wrapper functions.
########################################################################

import json
import os
import re
import time

from helpers import JsonHelper

from IdaProxy import IdaProxy
from idascope.core.structures.FunctionContext import FunctionContext
from idascope.core.structures.FunctionContextFilter import FunctionContextFilter
from idascope.core.structures.CallContext import CallContext
from idascope.core.structures.ParameterContext import ParameterContext


class SemanticIdentifier():
    """
    A module to analyze and explore an IDB for semantics. For a set of API names, references to these
    are identified and used for creating context and allowing tagging of them.
    """

    def __init__(self, idascope_config):
        print ("[|] loading SemanticIdentifier")
        self.os = os
        self.re = re
        self.time = time
        self.ida_proxy = IdaProxy()
        self.FunctionContext = FunctionContext
        self.FunctionContextFilter = FunctionContextFilter
        self.CallContext = CallContext
        self.ParameterContext = ParameterContext
        # fields
        self.semantics = {}
        self.active_semantics = {}
        self.renaming_seperator = "_"
        self.semantic_groups = []
        self.semantic_definitions = []
        self.real_api_names = {}
        self.last_scan_result = {}
        self.idascope_config = idascope_config
        self._getRealApiNames()
        self._loadSemantics(self.idascope_config)
        return

    def _cbEnumImports(self, addr, name, ordinal):
        if name:
            self.real_api_names[name] = self.ida_proxy.Name(addr)
        return True

    def _getRealApiNames(self):
        num_imports = self.ida_proxy.get_import_module_qty()
        for i in xrange(0, num_imports):
            self.ida_proxy.enum_import_names(i, self._cbEnumImports)

    def lookupRealApiName(self, api_name):
        if api_name in self.real_api_names:
            return self.real_api_names[api_name]
        else:
            return api_name

    def lookupDisplayApiName(self, real_api_name):
        """ returns the key by given value of self.real_api_names (basically inverted dictionary)
        """
        name = real_api_name
        for display_name in self.real_api_names:
            if real_api_name == self.real_api_names[display_name] \
                    and display_name in self.real_api_names[display_name]:
                name = display_name
        return name

    def _loadSemantics(self, config):
        """
        Loads a semantic configuration file and collects all definitions from it.
        @param config_filename: filename of a semantic configuration file
        @type config_filename: str
        """
        for filename in [fn for fn in self.os.listdir(config.inspection_profiles_folder) if fn.endswith(".json")]:
            loaded_file = self._loadSemanticsFile(config.inspection_profiles_folder + self.os.sep + filename)
            self.semantics[loaded_file["name"]] = loaded_file
        if config.inspection_default_semantics in self.semantics:
            self._setSemantics(config.inspection_default_semantics)
        elif len(self.semantics) > 0:
            self._setSemantics(sorted(self.semantics.keys())[0])
        else:
            self._setSemantics("")
        return

    def _loadSemanticsFile(self, semantics_filename):
        """
        Loads a semantic configuration file and collects all definitions from it.
        @param config_filename: filename of a semantic configuration file
        @type config_filename: str
        """
        semantics_file = open(semantics_filename, "r")
        semantics = semantics_file.read()
        return json.loads(semantics, object_hook=JsonHelper.decode_dict)

    def _setSemantics(self, semantics_entry):
        semantics_content = {}
        if semantics_entry in self.semantics:
            semantics_content = self.semantics[semantics_entry]
            self.renaming_seperator = semantics_content["renaming_seperator"]
            self.semantic_groups = semantics_content["semantic_groups"]
            self.semantic_definitions = semantics_content["semantic_definitions"]
            self.active_semantics = semantics_content
        else:
            self.renaming_seperator = "_"
            self.semantic_groups = []
            self.semantic_definitions = []
            self.active_semantics = {"name": "none"}
        self.scanByReferences()

    def getSemanticsNames(self):
        return sorted(self.semantics.keys())

    def getActiveSemanticsName(self):
        return self.active_semantics["name"]

    def calculateNumberOfBasicBlocksForFunctionAddress(self, function_address):
        """
        Calculates the number of basic blocks for a given function by walking its FlowChart.
        @param function_address: function address to calculate the block count for
        @type function_address: int
        """
        number_of_blocks = 0
        try:
            func_chart = self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_address))
            for block in func_chart:
                number_of_blocks += 1
        except:
            pass
        return number_of_blocks

    def getNumberOfBasicBlocksForFunctionAddress(self, address):
        """
        returns the number of basic blocks for the function containing the queried address,
        based on the value stored in the last scan result.

        If the number of basic blocks for this function has never been calculated, zero is returned.
        @param function_address: function address to get the block count for
        @type function_address: int
        @return: (int) The number of blocks in th e function
        """
        number_of_blocks = 0
        function_address = self.getFunctionAddressForAddress(address)
        if function_address in self.last_scan_result.keys():
            number_of_blocks = self.last_scan_result[function_address].number_of_basic_blocks
        return number_of_blocks

    def scan(self):
        """
        Scan the whole IDB with all available techniques.
        """
        self.scanByReferences()
        self.scanDeep()

    def scanByReferences(self):
        """
        Scan by references to API names, based on the definitions loaded from the config file.
        This is highly efficient because we only touch places in the IDB that actually have references
        to our API names of interest.
        """
        print ("  [/] SemanticIdentifier: Starting (fast) scan by references of function semantics.")
        time_before = self.time.time()
        self.last_scan_result = {}
        for semantic_tag in self.semantic_definitions:
            for api_name in semantic_tag["api_names"]:
                real_api_name = self.lookupRealApiName(api_name)
                api_address = self.ida_proxy.LocByName(real_api_name)
                for ref in self._getAllRefsTo(api_address):
                    function_ctx = self._getFunctionContext(ref)
                    function_ctx.has_tags = True
                    call_ctx = self.CallContext()
                    call_ctx.called_function_name = api_name
                    call_ctx.real_called_function_name = real_api_name
                    call_ctx.address_of_call = ref
                    call_ctx.called_address = api_address
                    call_ctx.tag = semantic_tag["tag"]
                    call_ctx.group = semantic_tag["group"]
                    call_ctx.parameter_contexts = self._resolveApiCall(call_ctx)
                    function_ctx.call_contexts.append(call_ctx)
        print ("  [\\] Analysis took %3.2f seconds." % (self.time.time() - time_before))

    def _getAllRefsTo(self, addr):
        code_ref_addrs = [ref for ref in self.ida_proxy.CodeRefsTo(addr, 0)]
        data_ref_addrs = [ref for ref in self.ida_proxy.DataRefsTo(addr)]
        return iter(set(code_ref_addrs).union(set(data_ref_addrs)))

    def _getNumRefsTo(self, addr):
        return sum([1 for ref in self._getAllRefsTo(addr)])

    def _getAllRefsFrom(self, addr, code_only=False):
        code_ref_addrs = [ref for ref in self.ida_proxy.CodeRefsFrom(addr, 0)]
        data_ref_addrs = []
        if code_only:
            # only consider data references that lead to a call near/far (likely imports)
            data_ref_addrs = [ref for ref in self.ida_proxy.DataRefsFrom(addr) if \
                self.ida_proxy.GetFlags(ref) & (self.ida_proxy.FL_CN | self.ida_proxy.FL_CF)]
        else:
            data_ref_addrs = [ref for ref in self.ida_proxy.DataRefsFrom(addr)]
        return iter(set(code_ref_addrs).union(set(data_ref_addrs)))

    def _getFunctionContext(self, addr):
        """
        Create or return an existing FunctionContext for the given address in the current scan result.
        @param func_addr: address to create a FunctionContext for
        @type func_addr: int
        @return: (FunctionContext) A reference to the corresponding function context
        """
        function_ctx = None
        function_address = self.ida_proxy.LocByName(self.ida_proxy.GetFunctionName(addr))
        if function_address not in self.last_scan_result.keys():
            function_ctx = self.FunctionContext()
            function_ctx.function_address = function_address
            function_ctx.function_name = self.ida_proxy.GetFunctionName(function_address)
            function_ctx.has_dummy_name = (self.ida_proxy.GetFlags(function_address) & \
                self.ida_proxy.FF_LABL) > 0
            self.last_scan_result[function_ctx.function_address] = function_ctx
        else:
            function_ctx = self.last_scan_result[function_address]
        return function_ctx

    def scanDeep(self):
        """
        Perform a full enumeration of all instructions,
        gathering information like number of instructions, number of basic blocks,
        references to and from functions etc.
        """
        print ("  [/] SemanticIdentifier: Starting deep scan of function semantics.")
        time_before = self.time.time()
        for function_ea in self.ida_proxy.Functions():
            function_chart = self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_ea))
            num_blocks = 0
            num_instructions = 0
            xrefs_from = []
            calls_from = []
            function_ctx = self._getFunctionContext(function_ea)
            for block in function_chart:
                num_blocks += 1
                for instruction in self.ida_proxy.Heads(block.startEA, block.endEA):
                    num_instructions += 1
                    if self.ida_proxy.isCode(self.ida_proxy.GetFlags(instruction)):
                        for ref in self._getAllRefsFrom(instruction):
                            if self.ida_proxy.GetMnem(instruction) == "call":
                                calls_from.append(ref)
                            xrefs_from.append(ref)
            function_ctx.calls_from.update(calls_from)
            function_ctx.number_of_xrefs_to = self._getNumRefsTo(function_ea)
            function_ctx.xrefs_from.update(xrefs_from)
            function_ctx.number_of_xrefs_from = len(xrefs_from)
            function_ctx.number_of_basic_blocks = num_blocks
            function_ctx.number_of_instructions = num_instructions
        print ("  [\\] Analysis took %3.2f seconds." % (self.time.time() - time_before))

    def getFunctionAddressForAddress(self, address):
        """
        Get a function address containing the queried address.
        @param address: address to check the function address for
        @type address: int
        @return: (int) The start address of the function containing this address
        """
        return self.ida_proxy.LocByName(self.ida_proxy.GetFunctionName(address))

    def calculateNumberOfFunctions(self):
        """
        Calculate the number of functions in all segments.
        @return: (int) the number of functions found.
        """
        number_of_functions = 0
        for seg_ea in self.ida_proxy.Segments():
            for function_ea in self.ida_proxy.Functions(self.ida_proxy.SegStart(seg_ea), self.ida_proxy.SegEnd(seg_ea)):
                number_of_functions += 1
        return number_of_functions

    def calculateNumberOfTaggedFunctions(self):
        """
        Calculate the number of functions in all segments that have been tagged.
        @return: (int) the number of functions found.
        """
        return len(self.getFunctionAddresses(self.createFunctionContextFilter()))

    def getFunctionAddresses(self, context_filter):
        """
        Get all function address that have been covered by the last scanning.
        @param dummy_only: only return functions with dummy names
        @type dummy_only: bool
        @param tag_only: only return tag functions
        @type tag_only: bool
        @return: (list of int) The addresses of covered functions.
        """
        all_addresses = self.last_scan_result.keys()
        filtered_addresses = []
        if context_filter.display_all:
            filtered_addresses = all_addresses
        elif context_filter.display_tags:
            for address in all_addresses:
                enabled_tags = [tag[0] for tag in context_filter.enabled_tags]
                if len(set(self.last_scan_result[address].getTags()) & set(enabled_tags)) > 0:
                    filtered_addresses.append(address)
        elif context_filter.display_groups:
            for address in all_addresses:
                enabled_groups = [group[0] for group in context_filter.enabled_groups]
                if len(set(self.last_scan_result[address].getGroups()) & set(enabled_groups)) > 0:
                    filtered_addresses.append(address)
        # filter additionals
        if context_filter.isDisplayTagOnly():
            filtered_addresses = [addr for addr in filtered_addresses if self.last_scan_result[addr].has_tags]
        if context_filter.isDisplayDummyOnly():
            filtered_addresses = [addr for addr in filtered_addresses if self.last_scan_result[addr].has_dummy_name]
        return filtered_addresses

    def getTags(self):
        """
        Get all the tags that have been covered by the last scanning.
        @return (list of str) The tags found.
        """
        tags = []
        for function_address in self.last_scan_result.keys():
            for call_ctx in self.last_scan_result[function_address].call_contexts:
                if call_ctx.tag not in tags:
                    tags.append(call_ctx.tag)
        return tags

    def getGroups(self):
        """
        Get all the groups that have been covered by tags in the last scanning.
        @return (list of str) The groups found.
        """
        tag_to_group_mapping = self._createTagToGroupMapping()
        groups = []
        for function_address in self.last_scan_result.keys():
            for call_ctx in self.last_scan_result[function_address].call_contexts:
                if tag_to_group_mapping[call_ctx.tag] not in groups:
                    groups.append(tag_to_group_mapping[call_ctx.tag])
        return groups

    def _createTagToGroupMapping(self):
        mapping = {}
        for definition in self.semantic_definitions:
            mapping[definition["tag"]] = definition["group"]
        return mapping

    def getTagsForFunctionAddress(self, address):
        """
        Get all tags found for the function containing the queried address.
        @param address: address in the target function
        @type address: int
        @return: (list of str) The tags for the function containing the queried address
        """
        tags = []
        function_address = self.getFunctionAddressForAddress(address)
        if function_address in self.last_scan_result.keys():
            for call_ctx in self.last_scan_result[function_address].call_contexts:
                if call_ctx.tag not in tags:
                    tags.append(call_ctx.tag)
        return tags

    def getFieldCountForFunctionAddress(self, query, address):
        """
        Get the number of occurrences for a certain field for the function containing the queried address.
        @param query: a tuple (type, name), where type is additional, tag, or group and name the field being queried.
        @type query: tuple
        @param address: address in the target function
        @type address: int
        @return: (int) The number of occurrences for this tag in the function
        """
        function_address = self.getFunctionAddressForAddress(address)
        return self.last_scan_result[function_address].getCountForField(query)

    def getTaggedApisForFunctionAddress(self, address):
        """
        Get all call contexts for the function containing the queried address.
        @param address: address in the target function
        @type address: int
        @return: (list of CallContext data objects) The call contexts identified by the scanning of this function
        """
        function_address = self.getFunctionAddressForAddress(address)
        if function_address in self.last_scan_result.keys():
            all_call_ctx = self.last_scan_result[function_address].call_contexts
            return [call_ctx for call_ctx in all_call_ctx if call_ctx.tag != ""]

    def getAddressTagPairsOrderedByFunction(self):
        """
        Get all call contexts for all functions
        @return: a dictionary with key/value entries of the following form: (function_address,
                 dict((call_address, tag)))
        """
        functions_and_tags = {}
        for function in self.getIdentifiedFunctionAddresses():
            call_contexts = self.getTaggedApisForFunctionAddress(function)
            if function not in functions_and_tags.keys():
                functions_and_tags[function] = {}
            for call_ctx in call_contexts:
                functions_and_tags[function][call_ctx.address_of_call] = call_ctx.tag
        return functions_and_tags

    def getFunctionsToRename(self):
        """
        Get all functions that can be renamed according to the last scan result. Only functions with the standard
        IDA name I{sub_[0-9A-F]+} will be considered for renaming.
        @return: a list of dictionaries, each consisting of three tuples: ("old_function_name", str), \
                 ("new_function_name", str), ("function_address", int)
        """
        functions_to_rename = []
        for function_address_to_tag in self.last_scan_result.keys():
            new_function_name = self.last_scan_result[function_address_to_tag].function_name
            # has the function still a dummy name?
            if self.ida_proxy.GetFlags(function_address_to_tag) & self.ida_proxy.FF_LABL > 0:
                tags_for_function = self.getTagsForFunctionAddress(function_address_to_tag)
                for tag in sorted(tags_for_function, reverse=True):
                    if tag not in new_function_name:
                        new_function_name = tag + self.renaming_seperator + new_function_name
                functions_to_rename.append({"old_function_name": \
                    self.last_scan_result[function_address_to_tag].function_name, "new_function_name": \
                    new_function_name, "function_address": function_address_to_tag})
        return functions_to_rename

    def renameFunctions(self):
        """
        Perform the renaming of functions according to the last scan result.
        """
        for function in self.getFunctionsToRename():
            if function["old_function_name"] == self.ida_proxy.GetFunctionName(function["function_address"]):
                self.ida_proxy.MakeNameEx(function["function_address"], function["new_function_name"], \
                    self.ida_proxy.SN_NOWARN)

    def renamePotentialWrapperFunctions(self):
        """
        contributed by Branko Spasojevic.
        """
        num_wrappers_renamed = 0
        for seg_ea in self.ida_proxy.Segments():
            for func_ea in self.ida_proxy.Functions(self.ida_proxy.SegStart(seg_ea), self.ida_proxy.SegEnd(seg_ea)):
                if (self.ida_proxy.GetFlags(func_ea) & 0x8000) != 0:
                    nr_calls, w_name = self._checkWrapperHeuristics(func_ea)
                    if nr_calls == 1 and len(w_name) > 0:
                        rval = False
                        name_suffix = 0
                        while rval == False:
                            if name_suffix > 40:
                                print("[!] Potentially more than 50 wrappers for function %s, " \
                                    "please report this IDB ;)" % w_name)
                                break
                            demangled_name = self.ida_proxy.Demangle(w_name, self.ida_proxy.GetLongPrm(self.ida_proxy.INF_SHORT_DN))
                            if demangled_name != None and demangled_name != w_name:
                                f_name = w_name + '_w' + str(name_suffix)
                            elif name_suffix > 0:
                                f_name = w_name + '_w' + str(name_suffix)
                            else:
                                f_name = w_name + '_w0'
                            name_suffix += 1
                            rval = self.ida_proxy.MakeNameEx(func_ea, f_name, \
                                self.ida_proxy.SN_NOCHECK | self.ida_proxy.SN_NOWARN)
                        if rval == True:
                            print("[+] Identified and renamed potential wrapper @ [%08x] to [%s]" % \
                                (func_ea, f_name))
                            num_wrappers_renamed += 1
        print("[+] Renamed %d functions with their potentially wrapped name." % num_wrappers_renamed)

    def _checkWrapperHeuristics(self, func_ea):
        """
        Helps renamePotentialWrapperFunctions() to decide whether the function analyzed is a wrapper or not.
        """
        nr_calls = 0
        w_name = ""
        # Heuristic: wrappers are likely short
        func_end = self.ida_proxy.GetFunctionAttr(func_ea, self.ida_proxy.FUNCATTR_END)
        if (func_end - func_ea) > 0 and (func_end - func_ea) < 0x40:
            return (0, "")
        # Heuristic: wrappers shall only have a single reference, ideally to a library function.
        for i_ea in self.ida_proxy.FuncItems(func_ea):
            # long jumps don't occur in wrappers considered by this code.
            if self.ida_proxy.GetMnem(i_ea) == 'jmp' \
                and (func_ea > self.ida_proxy.GetOperandValue(i_ea,0) \
                    or func_end < self.ida_proxy.GetOperandValue(i_ea,0)):
                   nr_calls += 2
            # checks if call is not memory reference
            if self.ida_proxy.GetMnem(i_ea) == 'call':
                nr_calls += 1
                if self.ida_proxy.GetOpType(i_ea,0) != 2 \
                    and self.ida_proxy.GetOpType(i_ea,0) != 6 \
                        and self.ida_proxy.GetOpType(i_ea,0) != 7:
                    nr_calls += 2
                if nr_calls > 1:
                    break
                call_dst = list(self.ida_proxy.CodeRefsFrom(i_ea, 0))
                if len(call_dst) == 0:
                    continue
                call_dst = call_dst[0]
                if (self.ida_proxy.GetFunctionFlags(call_dst) & self.ida_proxy.FUNC_LIB) != 0 or \
                    (self.ida_proxy.GetFlags(func_ea) & self.ida_proxy.FF_LABL) == 0:
                    w_name = self.ida_proxy.Name(call_dst)
        return (nr_calls, w_name)


    def getParametersForCallAddress(self, call_address):
        """
        Get the parameters for the given address of a function call.
        @param call_address: address of the target call to inspect
        @type call_address: int
        @return: a list of ParameterContext data objects.
        """
        target_function_address = self.ida_proxy.LocByName(self.ida_proxy.GetFunctionName(call_address))
        all_tagged_apis_in_function = self.getTaggedApisForFunctionAddress(target_function_address)
        for api in all_tagged_apis_in_function:
            if api.address_of_call == call_address:
                return self._resolveApiCall(api)
        return []

    def _resolveApiCall(self, call_context):
        """
        Resolve the parameters for an API calls based on a call context for this API call.
        @param call_context: the call context to get the parameter information for
        @type call_context: a CallContext data object
        @return: a list of ParameterContext data objects.
        """
        resolved_api_parameters = []
        api_signature = self._getApiSignature(call_context.real_called_function_name)
        push_addresses = self._getPushAddressesBeforeTargetAddress(call_context.address_of_call)
        resolved_api_parameters = self._matchPushAddressesToSignature(push_addresses, api_signature)
        return resolved_api_parameters

    def _matchPushAddressesToSignature(self, push_addresses, api_signature):
        """
        Combine the results of I{_getPushAddressesBeforeTargetAddress} and I{_getApiSignature} in order to
        produce a list of ParameterContext data objects.
        @param push_addresses: the identified push addresses before a function call that shall be matched to a function
                               signature
        @type push_addresses: a list of int
        @param api_signature: information about a function definition with
                              parameter names, types, and so on.
        @type api_signature: a dictionary with the layout as returned by I{_getApiSignature}
        @return: a list of ParameterContext data objects.
        """
        matched_parameters = []
        # TODO:
        # upgrade this feature with data flow analysis to resolve parameters with higher precision
        api_num_params = len(api_signature["parameters"])
        push_addresses = push_addresses[-api_num_params:]
        # TODO:
        # There might be the case where we identify less pushed parameters than required by the function
        # signature. Thus we calculate a "parameter discrepancy" that we use to adjust our enumeration index
        # so that the last n parameters get matched correctly. This is a temporary fix and might be solved later on.
        parameter_discrepancy = len(push_addresses) - api_num_params
        for index, param in enumerate(api_signature["parameters"], start=parameter_discrepancy):
            param_ctx = self.ParameterContext()
            param_ctx.parameter_type = param["type"]
            param_ctx.parameter_name = param["name"]
            if (parameter_discrepancy != 0) and (index < 0):
                param_ctx.valid = False
            else:
                param_ctx.push_address = push_addresses[index]
                param_ctx.ida_operand_type = self.ida_proxy.GetOpType(push_addresses[index], 0)
                param_ctx.ida_operand_value = self.ida_proxy.GetOperandValue(push_addresses[index], 0)
                param_ctx.value = param_ctx.ida_operand_value
            matched_parameters.append(param_ctx)
        return matched_parameters

    def _getApiSignature(self, api_name):
        """
        Get the signature for a function by using IDA's I{GetType()}. The string is then parsed with a Regex and
        returned as a dictionary.
        @param api_name: name of the API / function to get type information for
        @type api_name: str
        @return: a dictionary with key/value entries of the following form: ("return_type", str),
                 ("parameters", [dict(("type", str), ("name", str))])
        """
        api_signature = {"api_name": api_name, "parameters": []}
        api_location = self.ida_proxy.LocByName(api_name)
        type_def = self.ida_proxy.GetType(api_location)
        function_signature_regex = r"(?P<return_type>[\w\s\*]+)\((?P<parameters>[,\.\*\w\s]*)\)"
        result = self.re.match(function_signature_regex, type_def)
        if result is not None:
            api_signature["return_type"] = result.group("return_type")
            if len(result.group("parameters")) > 0:
                for parameter in result.group("parameters").split(","):
                    type_and_name = {}
                    type_and_name["type"] = parameter[:parameter.rfind(" ")].strip()
                    type_and_name["name"] = parameter[parameter.rfind(" "):].strip()
                    api_signature["parameters"].append(type_and_name)
        else:
            print ("[-] SemanticIdentifier._getApiSignature: No API/function signature for \"%s\" @ 0x%x available. " \
            + "(non-critical)") % (api_name, api_location)
        # TODO:
        # here should be a check for the calling convention
        # currently, list list is simply reversed to match the order parameters are pushed to the stack
        api_signature["parameters"].reverse()
        return api_signature

    def _getPushAddressesBeforeTargetAddress(self, address):
        """
        Get the addresses of all push instructions in the basic block preceding the given address.
        @param address: address to get the push addresses for.
        @type address: int
        @return: a list of int
        """
        push_addresses = []
        function_chart = self.ida_proxy.FlowChart(self.ida_proxy.get_func(address))
        for block in function_chart:
            if block.startEA <= address < block.endEA:
                for instruction_addr in self.ida_proxy.Heads(block.startEA, block.endEA):
                    if self.ida_proxy.GetMnem(instruction_addr) == "push":
                        push_addresses.append(instruction_addr)
                    if instruction_addr >= address:
                        break
        return push_addresses

    def createFunctionGraph(self, func_address):
        graph = {"root": func_address, "nodes": {}}
        unexplored = set()
        if func_address in self.last_scan_result.keys():
            graph["nodes"][func_address] = self.last_scan_result[func_address].calls_from
            unexplored = set(self.last_scan_result[func_address].calls_from)
            while len(unexplored) > 0:
                current_function = unexplored.pop()
                if current_function in graph["nodes"].keys() or current_function not in self.last_scan_result.keys():
                    continue
                else:
                    graph["nodes"][current_function] = self.last_scan_result[current_function].calls_from
                    new_functions = \
                        set(self.last_scan_result[current_function].calls_from).difference(set(graph["nodes"].keys()))
                    unexplored.update(new_functions)
        return graph

    def createFunctionContextFilter(self):
        """
        Create a function filter, containing only those tags/groups that have been identified within the last scan.
        """
        context_filter = self.FunctionContextFilter()
        context_filter.tags = sorted([(tag, tag, tag) for tag in self.getTags()])
        context_filter.enabled_tags = context_filter.tags
        context_filter.groups = sorted([(group, group, group) for group in self.getGroups()])
        context_filter.enabled_groups = context_filter.groups
        return context_filter

    def getLastScanResult(self):
        """
        Get the last scan result as retrieved by I{scanByReferences}.
        @return: a dictionary with key/value entries of the following form: (function_address, FunctionContext)
        """
        return self.last_scan_result

    def printLastScanResult(self):
        """
        nicely print the last scan result (mostly used for debugging)
        """
        for function_address in self.last_scan_result.keys():
            print ("0x%x - %s -> ") % (function_address, self.ida_proxy.GetFunctionName(function_address)) \
                + ", ".join(self.getTagsForFunctionAddress(function_address))
            for call_ctx in self.last_scan_result[function_address].call_contexts:
                print ("    0x%x - %s (%s)") % (call_ctx.address_of_call, call_ctx.called_function_name, call_ctx.tag)

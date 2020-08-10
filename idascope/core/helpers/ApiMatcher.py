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


class ApiMatcher():
    def __init__(self, parent, target_apis, enums, config):
        self.parent = parent
        self.cc = parent.cc
        self.signatures = self.cc.ApiSignatureResolver(self, target_apis)
        self.ida_proxy = self.cc.ida_proxy
        self.target_apis = target_apis
        self.enums = enums
        self.api_data = self.cc.ApiManager(self, self.target_apis)
        self.config = config

    def _hasTargetParameters(self, target_parameters):
        return target_parameters is not None

    def getFromSignature(self, api):
        api_dict = self.signatures.getApiSignature(api)
        if api_dict:
            return api_dict.get('parameters', {})
        return {}

    def listAll(self):
        return self.signatures.getAllSignatures()

    def getName(self, address, arg_position, arg_list):
        addr_comment =  self.ida_proxy.Comment(address)
        arg_type = [arg['type'] for arg in arg_list if addr_comment == arg['name'] or '*%s' % addr_comment == arg['name']]
        if not arg_type:
            return arg_list[arg_position]['name']
        return addr_comment

    def getType(self, arg_name, arg_list):
        for arg in arg_list:
            if arg['name'] == arg_name or '*%s' % arg['name'] == arg_name:
                return arg['type']
        return "unresolved"

    def getFromSuspiciousFlow(self, addr, signature_args):
        if signature_args:
            function_parents = self.api_data._getAllRefsFrom(addr)
            suspicious_args = self.api_data._getAPIArgs(addr, len(signature_args), function_parents)
            return self.parse(suspicious_args, signature_args)
        return []

    def parse(self, suspicious_args, signature_args):
        args = []
        for arg_number, address in enumerate(suspicious_args):
            arg_name = self.getName(address, arg_number, signature_args)
            arg_value = self.api_data._backtrace(address)[2]
            arg_type = self.getType(arg_name, signature_args)
            args.append({'arg_name': arg_name, 'arg_value': arg_value, 'arg_type': arg_type})
        return args

    def matchKeyEnum(self, arg_value, arg_number):
        enum_index = 0
        if arg_number == enum_index:
            enums = self.enums['MACRO_HKEY']
            if arg_value in enums.keys():
                arg_value = enums[arg_value]
        return arg_value

    def _matchArgumentsFromRegistrySemantics(self, argsOfSemantic, suspicious_args):
        matches = []
        for arg_number, arg_sequence in enumerate(suspicious_args):
            arg_name = arg_sequence.get("arg_name", "")
            arg_value = self.matchKeyEnum(arg_sequence.get("arg_value", ""), arg_number)
            for semantic_arg in argsOfSemantic:
                name = semantic_arg.get('name', '')
                value = semantic_arg.get('value', '')
                if arg_value.upper() in value and arg_name in name:
                    matches.append({
                        "arg_name": arg_name,
                        "arg_value": arg_value,
                        "arg_type": arg_sequence.get("arg_type", "")
                                    })
        if len(matches) == len(argsOfSemantic):
            return matches
        return []

    def _matchAllArgumentTypes(self, argsOfSemantic, suspicious_args):
        matches = []
        arg_count = len(argsOfSemantic)

        for semantic_dict in argsOfSemantic:
            value = semantic_dict.get("arg_value", "")
            for arg_sequence in suspicious_args:
                arg_name = arg_sequence.get("arg_name", "")
                arg_value = arg_sequence.get("arg_value", "")
                if value in arg_value.upper() and value in arg_name:
                    matches.append({
                        "arg_name": arg_name,
                        "arg_value": arg_value,
                        "arg_type": arg_sequence.get("arg_type", "")
                                    })
        if len(matches) == arg_count:
            return matches
        return []

    def getFlowArgs(self, call_name, call_addr):
        signature_args = self.getFromSignature(call_name)
        suspicious_args = self.getFromSuspiciousFlow(call_addr, signature_args)
        return suspicious_args

    def matchApiAndArguments(self, semantic_call, call):
        call_name, call_addr = call
        api, parameters = semantic_call

        if self._matchAPIs(api, call_name) and parameters:
            suspicious_args = self.getFlowArgs(call_name, call_addr)
            if api.startswith('Reg'):
                # Match Registry Semantics
                args = self._matchArgumentsFromRegistrySemantics(parameters, suspicious_args)
            else:
                # Match all Semantics containing arguments
                args = self._matchAllArgumentTypes(parameters, suspicious_args)
            if args:
                return ("0x%x" % call_addr, api, args)
        elif self._matchAPIs(api, call_name) and not parameters:
            suspicious_args = self.getFlowArgs(call_name, call_addr)
            return ("0x%x" % call_addr, api, suspicious_args)
        return None

    def _matchAPIs(self, apiOfSemantic, apiOfSequence, addr=0):
        try:
            apiOfSequence.decode("ascii")
        except:
            if self.config.debug:
                print "SemanticExplorer._matchAPIs - addr: 0x%x" % addr
                print "SemanticExplorer._matchAPIs - apiOfSequence: %s" % apiOfSequence.encode("hex")
            return False
        return apiOfSemantic in apiOfSequence


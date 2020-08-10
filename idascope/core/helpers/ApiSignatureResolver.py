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


class ApiSignatureResolver():

    def __init__(self, parent, semanticTargetApis):
        self.parent = parent
        self.cc = parent.cc
        self.ida_proxy = self.cc.ida_proxy
        self.semanticTargetApis = semanticTargetApis

    def getApiSignature(self, api_name):
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
        result = self.cc.re.match(function_signature_regex, type_def)
        if result is not None:
            api_signature["return_type"] = result.group("return_type")
            if len(result.group("parameters")) > 0:
                for parameter in result.group("parameters").split(","):
                    type_and_name = {}

                    type_and_name["type"] = parameter[:parameter.rfind(" ")].strip()
                    type_and_name["name"] = parameter[parameter.rfind(" "):].strip()
                    api_signature["parameters"].append(type_and_name)
            # TODO: here should be a check for the calling convention, currently,
            # list is simply reversed to match the order parameters are pushed to the stack
            #api_signature["parameters"].reverse()
            return api_signature
        return None

    def getAllSignatures(self):
        api_signatures = []
        missing_apis = []
        semantic_apis = self.semanticTargetApis

        for api_name in semantic_apis:
            #Search signature in IDA db
            signature_from_IDA = self.getApiSignature(api_name)

            if signature_from_IDA:
                api_signatures.append(signature_from_IDA)
            else:
                #Buffer missing api signature
                missing_apis.append(api_name)
        if missing_apis:
            print '[Error]: Analysis may be incomplete due to the following unresolved signatures',
            for missing in missing_apis:
                print missing
        return api_signatures




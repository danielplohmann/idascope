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
# based on Backtrace
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# https://bitbucket.org/Alexander_Hanel/backtrace
########################################################################


class ApiManager():

    def __init__(self, parent, targetSemanticApis):
        self.parent = parent
        self.cc = parent.cc
        self.ida_proxy = self.cc.ida_proxy
        self.target_apis = targetSemanticApis
        self.signatures = self.cc.ApiSignatureResolver(self, self.target_apis)
        self.registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']
        self.nonMov = True
        self.tainted = False
        self.nonReg = ''

    def _getApiRef(self, api_name):
        """
        Get all xrefs in code to an API
        @param api_name: name of the API / function to get type information for
        @type api_name: str
        @return: list of addresses where the API has been called
        """
        addr = self.ida_proxy.LocByName(api_name)
        apiAddrList = self._getAllRefsFrom(addr)
        return apiAddrList

    def _getRetRef(self, address):
        return self._getAllRefsTo(address)

    def _getAllRefsFrom(self, addr, code_only=False):
        """
        Get all xrefs from a given address
        @param addr: address to get xrefs for
        @type addr: ea
        @return: list of addresses
        """
        code_ref_addrs = [ref for ref in self.ida_proxy.CodeRefsFrom(addr, 0)]
        data_ref_addrs = []
        if code_only:
            data_ref_addrs = [ref for ref in self.ida_proxy.DataRefsFrom(addr) if
                              self.ida_proxy.GetFlags(ref) & (self.ida_proxy.FL_CN | self.ida_proxy.FL_CF)]
        else:
            data_ref_addrs = [ref for ref in self.ida_proxy.DataRefsFrom(addr)]
        return list(set(code_ref_addrs).union(set(data_ref_addrs)))

    def _getAllRefsTo(self, addr, code_only=False):
        """
        Get all xrefs to a given address
        @param addr: address to get xrefs for
        @type addr: ea
        @return: list of addresses
        """
        code_ref_addrs = [ref for ref in self.ida_proxy.CodeRefsTo(addr, 0)]
        data_ref_addrs = [ref for ref in self.ida_proxy.DataRefsTo(addr)]
        return iter(set(code_ref_addrs).union(set(data_ref_addrs)))

    def _getAPIArgs(self, api_addr, arg_count, funcParents):
        """Collects all push in a call sequence @funcParents starting at address @api_addr
        @api_addr: address from where to start searching for a 'push'
        @arg_count: number of push to find
        @funcParents: list of functions that belong to the call sequence
        @return: list of addresses"""
        args = []
        maxDepth = 5

        #Find local args pushed to the stack
        args = self._getPush(api_addr, arg_count)
        #Did it find all args?
        missingArgs = arg_count - len(args)
        #Yes
        if missingArgs == 0:
            return args
        #No
        while missingArgs > 0 and maxDepth > 0:
            #search for pushed args in functions that contains a reference to api_addr (callers of that API)
            for function in funcParents:
                if not function:
                    continue
                new_args = self._getPush(function, missingArgs)
                for new in new_args:
                    if arg_count - len(args) > 0:
                        args.append(new)
                missingArgs = arg_count - len(args)
            maxDepth -= 1

        if missingArgs > 0:
            print '[WARNING]: Not possible to track all arguments for ', "0x%x" % api_addr
        return args

    def _getPush(self, address, arg_count):
        """Collects all lines in code wich contains a push starting at @address
        @address: address from where to start searching for a 'push'
        @arg_count: number of push to find
        @return: list of addresses"""

        push_count = 0
        args = []
        prevLine = self.ida_proxy.PrevHead(address, 0)
        funcStart = self.ida_proxy.GetFunctionAttr(address, self.ida_proxy.FUNCATTR_START)

        while prevLine >= funcStart:
            instruction = self.ida_proxy.GetDisasm(prevLine)
            if instruction:
                instruction = instruction.split()[0]
            if 'push' == instruction and len(args) < arg_count:
                args.append(prevLine)
                push_count += 1
                if push_count == arg_count:
                    return args
            prevLine = self.ida_proxy.PrevHead(prevLine, 0)
        return args

    def GPRPurpose(self, register):
        if register in ['al', 'ah', 'ax', 'eax', 'rax']:
            return 'accumulator'
        if register in ['bl', 'bh', 'bx', 'ebx', 'rbx']:
            return 'base'
        if register in ['cl', 'ch', 'cx', 'ecx', 'rcx']:
            return 'counter'
        if register in ['dl', 'dh', 'dx', 'edx', 'rdx']:
            return 'extend'
        if register in ['si', 'esi', 'rsi']:
            return 'source'
        if register in ['di', 'edi', 'rdi']:
            return 'dest'
        if register in ['sp', 'esp', 'rbp']:
            return 'stack'
        if register in ['bp', 'ebp', 'rbp']:
            return 'base'
        if register in ['ip', 'eip', 'rip']:
            return 'instru'
        return None

    def inDism(self, dism, pur):
        s = dism.replace(',', '').split()
        if len(s) > 1:
            del s[0]
        for op in s:
            results = self.GPRPurpose(op)
            if results:
                return pur == results
        return False

    def _backtrace(self, address):
        """Finds references of registers and args based on string and function argument parsing.
        @address: address from where to start searching
        @return: address where started searching, address where the register was populated and
        the register value"""

        push = self.ida_proxy.GetOpnd(address, 0)
        arg = self.parseOperand(push)
        purpose = self.GPRPurpose(push)
        currentAddress = self.ida_proxy.PrevHead(address)
        dism = self.ida_proxy.GetDisasm(currentAddress)

        funcStart = self.ida_proxy.GetFunctionAttr(address, self.ida_proxy.FUNCATTR_START)

        while(currentAddress >= funcStart):
            # check for reg being used as a pointer [eax]
            for reg in self.registers:
                ptreg = '[' + reg + ']'
                if push == ptreg:
                    push = reg
                    purpose = self.GPRPurpose(push)

            if push.isdigit():
                return (address, address, push)

            if 'call' in dism and push == 'eax':
                return (address, currentAddress, self.ida_proxy.GetOpnd(currentAddress, 0))

            if push in dism or self.inDism(dism, purpose):
                mnem = self.ida_proxy.GetMnem(currentAddress)
                if mnem in ['mov', 'movsx', 'movzx', 'xchg']:
                    if push in self.ida_proxy.GetOpnd(currentAddress, 0) or self.inDism(self.ida_proxy.GetOpnd(currentAddress, 0), purpose):
                        operand = self.ida_proxy.GetOpnd(currentAddress, 1)
                        purpose = self.GPRPurpose(push)
                        arg = "%s:%s"%(purpose, self.parseOperand(operand))
                if self.nonMov:
                    if mnem in ['bswap']:
                        if push in self.ida_proxy.GetOpnd(currentAddress,0) or self.inDism(self.ida_proxy.GetOpnd(currentAddress,0), purpose):
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))

                    if mnem in ['xadd']:
                        #exchanged/temporary value. Not modified. See example above
                        if push in self.ida_proxy.GetOpnd(currentAddress, 1) or self.inDism(self.ida_proxy.GetOpnd(currentAddress, 1), purpose):
                            operand = self.ida_proxy.GetOpnd(currentAddress,0)
                            purpose = self.GPRPurpose(push)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))
                        #calculated value. basically add
                        elif push in self.ida_proxy.GetOpnd(currentAddress,0) or self.inDism(self.ida_proxy.GetOpnd(currentAddress,0), purpose):
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))

                    # Logical Instructions
                    if mnem in ['and', 'or', 'xor', 'not']:
                        if push in self.ida_proxy.GetOpnd(currentAddress,0) or self.inDism(self.ida_proxy.GetOpnd(currentAddress,0), purpose):
                            #lastRef = (currentAddress, self.ida_proxy.GetDisasm(currentAddress))
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))
                            #if mnem in ['xor'] and self.ida_proxy.GetOpnd(currentAddress,0) == self.ida_proxy.GetOpnd(currentAddress,1):

                    # Shift and Rotate Instructions
                    if mnem in ['sar', 'shr', 'sal', 'shl', 'shrd', 'shld', 'ror', 'rol', 'rcr', 'rcl']:
                        if push in self.ida_proxy.GetOpnd(currentAddress,0) or self.inDism(self.ida_proxy.GetOpnd(currentAddress,0), purpose):
                            #lastRef = (currentAddress, self.ida_proxy.GetDisasm(currentAddress))
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))

                    # Binary Arithmetic Instructions, dest source based
                    if mnem in ['add', 'adc', 'sub', 'sbb', 'inc', 'dec', 'neg']:
                        if push in self.ida_proxy.GetOpnd(currentAddress,0) or self.inDism(self.ida_proxy.GetOpnd(currentAddress,0), purpose):
                            #lastRef = (currentAddress, self.ida_proxy.GetDisasm(currentAddress))
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))

                    # Binary Arthimetic Instructions - quadword operand
                    if mnem in ['imul', 'mul', 'idiv', 'div']:
                        if push in self.ida_proxy.GetOpnd(currentAddress,0) or self.inDism(self.ida_proxy.GetOpnd(currentAddress,0), purpose):
                            #lastRef = (currentAddress, self.ida_proxy.GetDisasm(currentAddress))
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))

                    if mnem in ['lea']:
                        if self.inDism(self.ida_proxy.GetOpnd(currentAddress,0), purpose):
                        #if var in GetOpnd(currentAddress,0): REMOVE
                            #lastRef = (currentAddress, self.ida_proxy.GetDisasm(currentAddress))
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))

                    if mnem in ['cpuid']:
                        if self.inDism(push, 'accumulator') or self.inDism(push, 'counter'):
                            #lastRef = (currentAddress, self.ida_proxy.GetDisasm(currentAddress))
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))
                            return (address, currentAddress, arg)

                    if mnem in ['xlat', 'xlatb']:
                        if self.inDism(push, 'accumulator'):
                        #if var in ['eax', 'ah' 'al']: REMOVE
                            #lastRef = (currentAddress, self.ida_proxy.GetDisasm(currentAddress))
                            operand = self.ida_proxy.GetOpnd(currentAddress, 0)
                            arg = "%s:%s"%(purpose, self.parseOperand(operand))
                            return (address, currentAddress, arg)

            currentAddress = self.ida_proxy.PrevHead(currentAddress)
            dism = self.ida_proxy.GetDisasm(currentAddress)

        return (address, address, arg)

    def _readString(self, addr, isUnicode=False):
        """(Sality sample)
        - Example for 'purity_control'
        print _readString(0x422370)

        - Example for 'osDevives\amsint32' (unicode)
        print _readString(0x421a50, True)"""
        try:
            result = ''
            increment = 1
            if isUnicode:
                increment = 2
            index = 0

            while True:
                byte = self.ida_proxy.Byte(addr + index)
                if byte is not 0:
                    result += chr(byte)
                    index += increment
                else:
                    break
            return result
        except ValueError:
            return addr

    def _getSuspiciousBasicBlockCalls(self, block):
        calls = []
        start, end = block
        for instruction in self.ida_proxy.Heads(start, end):
            code = self.ida_proxy.GetMnem(instruction)

            if code == "call":
                xrefs = self._getAllRefsFrom(instruction)
                if xrefs:
                    call = self._getForwardedCall(xrefs)
                else:
                    call = self.getReferencedApiString(instruction)
                calls.append((call, instruction))

            if code == "jmp":
                operand = self.ida_proxy.GetOpnd(instruction, 0)
                addr = self.ida_proxy.LocByName(operand)
                if addr in self.ida_proxy.Functions():
                    calls.append((operand, instruction))
        return calls

    def parseOperand(self, operand):
        #Parameter is String
        if operand:
            access_addr = self.ida_proxy.LocByName(operand)
            return self.getReferencedString(access_addr, operand)
        #Parameter us Unknown
        return operand

    def getReferencedString(self, addr, operand):
        if self.ida_proxy.GetDisasm(addr):
            value_access = self._getDirectAccessToString(addr, operand)
            if self.isStringArg(value_access):
                return self._readString(value_access, self.isUnicode(value_access))
        return operand

    def isStringArg(self, value_access):
        disasm = str(self.ida_proxy.GetDisasm(value_access)).replace(' ', '')
        if disasm in 'db?;' or not disasm.endswith(', 0'):
            return False
        return True

    def _getDirectAccessToString(self, addr, opnd_value):
        try:
            #Parameter is referenced
            if self.isReferenced(addr):
                return self.ida_proxy.Dword(opnd_value)
        except TypeError:
            pass
        #Parameter is direct access
        return addr

    def isReferenced(self, addr):
        if 'offset' in self.ida_proxy.GetDisasm(addr):
            return True
        return False

    def isUnicode(self, string_addr):
        if 'unicode' in self.ida_proxy.GetDisasm(string_addr):
            return True
        return False

    def getReferencedApiString(self, instruction):
        try:
            call = self._readString(instruction)
        except TypeError:
            call = self.ida_proxy.GetOpnd(instruction, 0)
        return call

    def _isSuspiciousApi(self, call):
        for api in self.target_apis:
            if api in call:
                return True
        if call in self.ida_proxy.Functions:
            return True
        return False

    def _getForwardedCall(self, xrefs):
        sub_call = xrefs[0]
        return self.ida_proxy.Name(sub_call)


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
# - Scanning algorithm for certificates is based on work by
#   kyprizel's dump_certs.py
#     (http://www.kyprizel.net/work/ida/getkeys.py)
#   which is in turn based on work by Tobias Klein
#     (http://www.trapkit.de/research/sslkeyfinder/)
########################################################################


class CryptoIdentifier():
    """
    This class contains the logic to perform Crypto identification.
    Two techniques are currently supported:
    1. A heuristic approach that identifies functions and basic blocks
    based on the ratio of arithmetic/logic instructions to all instructions
    2. A signature-based approach, using the signatures defined in PatternManager
    """

    def __init__(self, config):
        self.name = "CryptoIdentifier"
        print ("[|] loading CryptoIdentifier")
        self.cc = config.class_collection
        self.time = self.cc.time
        self.re = self.cc.re
        self.ida_proxy = self.cc.ida_proxy
        self.graph_helper = self.cc.GraphHelper(self.cc)
        self.pm = self.cc.PatternManager(self)
        self.low_rating_threshold = 0.4
        self.high_rating_threshold = 1.0
        self.low_instruction_threshold = 8
        self.high_instruction_threshold = 100
        # if the threshold is set to this value, it is automatically expanded to infinite.
        self.max_instruction_threshold = 100
        self.low_call_threshold = 0
        self.high_call_threshold = 1
        # if the threshold is set to this value, it is automatically expanded to infinite.
        self.max_call_threshold = 10
        # if at least this fraction of a signature's length' has been identified
        # consecutively, the location is marked as a signature hit.
        self.match_filter_factor = 0.5
        self.aritlog_blocks = []
        self.signature_hits = []
        return

    def scan(self):
        """
        Scan the whole IDB with all available techniques.
        """
        self.scanAritlog()
        self.scanCryptoPatterns()

################################################################################
# Aritlog scanning
################################################################################

    def scanAritlog(self):
        """
        scan with the arithmetic/logic heuristic
        @return: a list of AritLogBasicBlock data objects that fulfill the parameters as specified
        """
        print ("  [/] CryptoIdentifier: Starting aritlog heuristic analysis.")
        self.aritlog_blocks = []
        time_before = self.time.time()
        for function_ea in self.ida_proxy.Functions():
            function_chart = self.ida_proxy.FlowChart(self.ida_proxy.get_func(function_ea))
            calls_in_function = 0
            function_blocks = []
            function_dgraph = {}
            blocks_in_loops = set()
            for current_block in function_chart:
                block = self.cc.AritlogBasicBlock(current_block.startEA, current_block.endEA)
                for instruction in self.ida_proxy.Heads(block.start_ea, block.end_ea):
                    if self.ida_proxy.isCode(self.ida_proxy.GetFlags(instruction)):
                        mnemonic = self.ida_proxy.GetMnem(instruction)
                        has_identical_operands = self.ida_proxy.GetOperandValue(instruction, 0) == \
                            self.ida_proxy.GetOperandValue(instruction, 1)
                        block.updateInstructionCount(mnemonic, has_identical_operands)
                        if mnemonic == "call":
                            calls_in_function += 1
                function_blocks.append(block)
                # prepare graph for Tarjan's algorithm
                succeeding_blocks = [succ.startEA for succ in current_block.succs()]
                function_dgraph[current_block.startEA] = succeeding_blocks
                # add trivial loops
                if current_block.startEA in succeeding_blocks:
                    block.is_contained_in_trivial_loop = True
                    blocks_in_loops.update([current_block.startEA])
            # perform Tarjan's algorithm to identify strongly connected components (= loops) in the function graph
            strongly_connected = self.graph_helper.calculateStronglyConnectedComponents(function_dgraph)
            non_trivial_loops = [component for component in strongly_connected if len(component) > 1]
            for component in non_trivial_loops:
                for block in component:
                    blocks_in_loops.update([block])
            for block in function_blocks:
                if block.start_ea in blocks_in_loops:
                    block.is_contained_in_loop = True
                block.num_calls_in_function = calls_in_function
            self.aritlog_blocks.extend(function_blocks)
        print ("  [\\] Analysis took %3.2f seconds." % (self.time.time() - time_before))

        return self.getAritlogBlocks(self.low_rating_threshold, self.high_rating_threshold,
            self.low_instruction_threshold, self.high_instruction_threshold,
            self.low_call_threshold, self.high_call_threshold,
            False, False, False)

    def _updateThresholds(self, min_rating, max_rating, min_instr, max_instr, min_call, max_call):
        """
        update all six threshold bounds
        @param min_rating: the minimum arit/log ratio a basic block must have
        @type min_rating: float
        @param max_rating: the maximum arit/log ratio a basic block can have
        @type max_rating: float
        @param min_instr: the minimum number of instructions a basic block must have
        @type min_instr: int
        @param max_instr: the minimum number of instructions a basic block can have
        @type max_instr: int
        @param min_call: the minimum number of calls a basic block must have
        @type min_call: int
        @param max_call: the minimum number of calls a basic block can have
        @type max_call: int
        """
        self.low_rating_threshold = max(0.0, min_rating)
        self.high_rating_threshold = min(1.0, max_rating)
        self.low_instruction_threshold = max(0, min_instr)
        if max_instr >= self.max_instruction_threshold:
            # we cap the value here and safely assume there is no block with more than 1000000 instructions
            self.high_instruction_threshold = 1000000
        else:
            self.high_instruction_threshold = max_instr
        self.low_call_threshold = max(0, min_call)
        if max_call >= self.max_call_threshold:
            # we cap the value here and safely assume there is no block with more than 1000000 instructions
            self.high_call_threshold = 1000000
        else:
            self.high_call_threshold = max_call

    def getAritlogBlocks(self, min_rating, max_rating, min_instr, max_instr, min_api, max_api, is_nonzero, \
        is_looped, is_trivially_looped):
        """
        get all blocks that are within the limits specified by the heuristic parameters.
        parameters are the same as in function "_updateThresholds" except
        param is_nonzero: defines whether zeroing instructions (like xor eax, eax) shall be counted or not.
        type is_nonzero: boolean
        param is_looped: defines whether only basic blocks in loops shall be selected
        type is_looped: boolean
        @return: a list of AritlogBasicBlock data objects, according to the parameters
        """
        self._updateThresholds(min_rating, max_rating, min_instr, max_instr, min_api, max_api)
        return [block for block in self.aritlog_blocks if
            (self.high_rating_threshold >= block.getAritlogRating(is_nonzero) >= self.low_rating_threshold) and
            (self.high_instruction_threshold >= block.num_instructions >= self.low_instruction_threshold) and
            (self.high_call_threshold >= block.num_calls_in_function >= self.low_call_threshold) and
            (not is_looped or block.is_contained_in_loop) and
            (not is_trivially_looped or block.is_contained_in_trivial_loop)]

    def getUnfilteredBlockCount(self):
        """
        returns the number of basic blocks that have been analyzed.
        @return: (int) number of basic blocks
        """
        return len(self.aritlog_blocks)

################################################################################
# Signature scanning
################################################################################

    def getSegmentData(self):
        """
        returns the raw bytes of the segments as stored by IDA
        @return: a list of Segment data objects.
        """
        segments = []
        for segment_ea in self.ida_proxy.Segments():
            try:
                segment = self.cc.Segment()
                segment.start_ea = segment_ea
                segment.end_ea = self.ida_proxy.SegEnd(segment_ea)
                segment.name = self.ida_proxy.SegName(segment_ea)
                buf = ""
                for ea in self.cc.Misc.lrange(segment_ea, self.ida_proxy.SegEnd(segment_ea)):
                    buf += chr(self.ida_proxy.get_byte(ea))
                segment.data = buf
                segments.append(segment)
            except:
                print ("[!] Tried to access invalid segment data. An error has occurred while address conversion")
        return segments

    def scanCryptoPatterns(self, pattern_size=32):
        """
        perform a scan ofr signatures. For matching, the standard python re module is used.
        @return: A list of CryptoSignatureHit data objects
        """
        crypt_results = []
        print ("  [/] CryptoIdentifier: Starting crypto signature scanning.")
        time_before_matching = self.time.time()
        segments = self.getSegmentData()
        print ("  [|] Segments under analysis: ")
        for segment in segments:
            print ("      " + str(segment))
        print ("  [|] PatternManager initialized, number of signatures: %d" % len(self.pm.signatures))
        keywords = self.pm.getTokenizedSignatures(pattern_size)
        print ("  [|] PatternManager tokenized patterns into %d chunks of %d bytes" % \
            (len(keywords.keys()), pattern_size))
        for keyword in keywords.keys():
            for segment in segments:
                crypt_results.extend([self.cc.CryptoSignatureHit(segment.start_ea + match.start(), \
                    keywords[keyword], keyword) for match in self.re.finditer(self.re.escape(keyword), segment.data)])
        print ("  [|] PatternManager now scanning variable signatures")
        variable_matches = self.scanVariablePatterns()
        crypt_results.extend(variable_matches)
        print ("  [\\] Full matching took %3.2f seconds and resulted in %d hits." % \
            (self.time.time() - time_before_matching, \
            len(crypt_results)))
        self.signature_hits = crypt_results
        return crypt_results

    def scanVariablePatterns(self):
        # the scanning code is roughly based on kyprizel's signature scan, see credtis above for more information
        crypt_results = []
        decoded_base64 = self.getDecodedBase64Strings()
        temporary_segment = self.mapBase64ToTemporarySegment(decoded_base64)
        variable_signatures = self.pm.getVariableSignatures()
        for var_sig in variable_signatures.keys():
            current_seg = self.ida_proxy.FirstSeg()
            seg_end = self.ida_proxy.SegEnd(current_seg)
            while current_seg != self.ida_proxy.BAD_ADDR:
                signature_hit = self.ida_proxy.find_binary(current_seg, seg_end, variable_signatures[var_sig], 16, 1)
                if signature_hit != self.ida_proxy.BAD_ADDR:
                    crypt_results.append(self.cc.CryptoSignatureHit(signature_hit, \
                        [var_sig], variable_signatures[var_sig]))
                    current_seg = signature_hit + variable_signatures[var_sig].count(" ") + 1
                else:
                    current_seg = self.ida_proxy.NextSeg(seg_end)
                    if not current_seg == self.ida_proxy.BAD_ADDR:
                        seg_end = self.ida_proxy.SegEnd(current_seg)
            if temporary_segment is not None and seg_end == temporary_segment:
                current_seg = temporary_segment
                seg_end = self.ida_proxy.SegEnd(current_seg)
                while current_seg != self.ida_proxy.BAD_ADDR:
                    signature_hit = self.ida_proxy.find_binary(current_seg, seg_end, variable_signatures[var_sig], 16, 1)
                    if signature_hit != self.ida_proxy.BAD_ADDR:
                        string_addr = self.extractAddr(signature_hit - temporary_segment, decoded_base64)
                        crypt_results.append(self.cc.CryptoSignatureHit(string_addr, \
                            [var_sig], variable_signatures[var_sig]))
                        current_seg = signature_hit + variable_signatures[var_sig].count(" ") + 1
                    else:
                        break
        if temporary_segment is not None:
            self.ida_proxy.DelSeg(temporary_segment, self.ida_proxy.SEGMOD_KILL)
        return crypt_results

    def extractAddr(self, signature_hit, decoded_base64):
        string_addr = 0
        for base in decoded_base64:
            if base[1] <= signature_hit:
                string_addr = base[0]
            else:
                break
        return string_addr

    def getDecodedBase64Strings(self):
        decoded_names = []
        byte_count = 0
        for name in self.ida_proxy.Names():
            flags = self.ida_proxy.GetFlags(name[0])
            if not self.ida_proxy.isASCII(flags):
                continue
            ascii = self.ida_proxy.GetString(name[0])
            try:
                b64 = ascii.decode("base64")
                decoded_names.append((name[0], byte_count, b64))
                byte_count += len(b64)
            except:
                continue
        return decoded_names

    def mapBase64ToTemporarySegment(self, decoded_base64):
        if len(decoded_base64) == 0:
            print ("[!] No base64 strings found, skipping scanning of decoded strings.")
            return None
        byte_count = decoded_base64[-1][1] + len(decoded_base64[-1][2])
        # get end of final segment to spawn a new one at that location, write decoded bytes there, search
        current_seg = self.ida_proxy.FirstSeg()
        seg_end = 0
        while current_seg != self.ida_proxy.BAD_ADDR:
            current_seg = self.ida_proxy.NextSeg(seg_end)
            if not current_seg == self.ida_proxy.BAD_ADDR:
                seg_end = self.ida_proxy.SegEnd(current_seg)
        print ("[|] PatternManager is creating a temporary segment to allow scanning of decoded base64 strings.")
        self.ida_proxy.AddSeg(seg_end, seg_end + byte_count, 0, True, self.ida_proxy.SA_REL_PARA, self.ida_proxy.SC_PUB)
        self.ida_proxy.SegRename(seg_end, "scopetmp")
        offset = seg_end
        for b64 in decoded_base64:
            for byte in b64[2]:
                self.ida_proxy.PatchByte(offset, ord(byte))
                offset += 1
        return seg_end

    def getSignatureLength(self, signature_name):
        """
        returns the length for a signature, identified by its name
        @param signature_name: name for a signature, e.g. "ADLER 32"
        @type signature_name: str
        @return: (int) length of the signature.
        """
        for item in self.pm.signatures.items():
            if item[1] == signature_name:
                return len(item[0])
        return 0

    def getXrefsToAddress(self, address):
        """
        get all references to a certain address.
        These are no xrefs in IDA sense but references to the crypto signatures.
        If the signature points to an instruction, e.g. if a constant is moved to a register, the return is flagged as
        "True", meaning it is an in-code reference.
        @param address: an arbitrary address
        @type address: int
        @return: a list of tuples (int, boolean)
        """
        xrefs = []
        head_to_address = self.ida_proxy.PrevHead(address, address - 14)
        if head_to_address != 0xFFFFFFFF:
            flags = self.ida_proxy.GetFlags(head_to_address)
            if self.ida_proxy.isCode(flags):
                xrefs.append((head_to_address, True))
        for x in  self.ida_proxy.XrefsTo(address):
            flags = self.ida_proxy.GetFlags(x.frm)
            if self.ida_proxy.isCode(flags):
                xrefs.append((x.frm, False))
        return xrefs

    def getSignatureHits(self):
        """
        Get all signature hits that have a length of at least match_filter_factor percent
        of the signature they triggered.
        Hits are grouped by signature names.
        @return: a dictionary  with key/value entries of the following form: ("signature name", [CryptoSignatureHit])
        """
        sorted_hits = sorted(self.signature_hits)
        unified_hits = []

        previous_signature_names = []
        for hit in sorted_hits:
            hit_intersection = [element for element in hit.signature_names if element in previous_signature_names]
            if len(hit_intersection) == 0:
                previous_signature_names = hit.signature_names
                unified_hits.append(self.cc.CryptoSignatureHit(hit.start_address, hit.signature_names, \
                    hit.matched_signature))
            else:
                previous_signature_names = hit_intersection
                previous_hit = unified_hits[-1]
                if hit.start_address == previous_hit.start_address + len(previous_hit.matched_signature):
                    previous_hit.matched_signature += hit.matched_signature
                    previous_hit.signature_names = hit_intersection
                else:
                    unified_hits.append(self.cc.CryptoSignatureHit(hit.start_address, hit.signature_names, \
                        hit.matched_signature))

        filtered_hits = []
        for hit in unified_hits:
            if len(hit.matched_signature) >= max([self.match_filter_factor * \
                self.getSignatureLength(name) for name in hit.signature_names]):
                hit.code_refs_to = self.getXrefsToAddress(hit.start_address)
                filtered_hits.append(hit)

        grouped_hits = {}
        for hit in filtered_hits:
            for name in hit.signature_names:
                if name not in grouped_hits:
                    grouped_hits[name] = [hit]
                else:
                    grouped_hits[name].append(hit)

        return grouped_hits

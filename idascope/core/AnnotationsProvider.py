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

from helpers import JsonHelper

annotations = {
               0x401000:
                 {
                  "function_name": "a_function_name",
                  "basic_blocks":
                    {
                     0x401010:
                       {
                        "color": 0xFF0000,
                        "annotations":
                          {
                           0x401012:
                             {
                              "instruction": "int 2d",
                              "comment": "a_comment",
                              "repeatable_comment": "a_repeatable_comment",
                              "color": 0xFF0000
                             }
                          }
                       }
                    }
                 }
              }


class AnnotationsProvider():

    def __init__(self):
        return

    def _loadConfig(self, config_filename):
        # TODO adapt implementation for this module
        config_file = open(config_filename, "r")
        config = config_file.read()
        parsed_config = json.loads(config, object_hook=JsonHelper.decode_dict)
        self.renaming_seperator = parsed_config["renaming_seperator"]
        self.semantic_definitions = parsed_config["semantic_definitions"]
        return

    def getAnnotations(self):
        # return: function:

        # FLAGs that help to identify names:
            # iterate via Names() to get addresses
            # use the following functions to dissect the names
            # idaapi.isCode()
            # idaapi.isData()
            # idaapi.has_cmt()
            # idaapi.isVar()
            # idaapi.has_name()
            # idaapi.has_user_name()
            # idaapi.has_auto_name()
            # idaapi.has_dummy_name()
        # open issues
            # names of stackvars?
        pass

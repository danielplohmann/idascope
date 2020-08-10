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


class IDAscopeConfiguration():
    """
    This class is an information container for a segment.
    """

    def __init__(self, configuration, class_collection):
        self.class_collection = class_collection
        self.cc = class_collection
        # default configuration
        self.idascope_plugin_only = False
        self.debug = False
        self.root_file_path = ""
        self.icon_file_path = ""
        self.inspection_tags_file = ""
        self.inspection_profiles_folder = ""
        self.winapi_keywords_file = ""
        self.winapi_rootdir = ""
        self.winapi_shortcut = "ctrl+y"
        self.winapi_load_keyword_database = False
        self.winapi_online_enabled = False
        #
        self.smtx_enum_file = ""
        self.smtx_semantics_file = ""
        #
        self.yara_sig_folders = []
        self._loadConfig(configuration)

    def _loadConfig(self, configuration):
        self.root_file_path = configuration["paths"]["idascope_root_dir"]
        # options directly affecting IDAscope
        self.idascope_plugin_only = configuration["plugin_only"]
        self.debug = configuration["debug"]
        # file path to the directory containing icons used by IDAscope
        self.icon_file_path = self.root_file_path + self.cc.os.sep \
            + "idascope" + self.cc.os.sep + "icons" + self.cc.os.sep
        # parse other paths
        self.config_path_sep = configuration["config_path_sep"]
        self.inspection_tags_file = self.root_file_path + self.cc.os.sep \
            + self._normalizePath(configuration["paths"]["inspection_tags_file"])
        self.inspection_profiles_folder = self.root_file_path + self.cc.os.sep \
            + self._normalizePath(configuration["paths"]["inspection_profiles_folder"])
        self.winapi_keywords_file = self.root_file_path + self.cc.os.sep + \
            self._normalizePath(configuration["paths"]["winapi_keywords_file"])
        if self.cc.os_path.isdir(self._normalizePath(configuration["paths"]["winapi_rootdir"])):
            #  winapi_rootdir is a file path
            self.winapi_rootdir = self._normalizePath(configuration["paths"]["winapi_rootdir"]) + self.cc.os.sep
        elif self.cc.os_path.isdir(self.root_file_path + self.cc.os.sep + \
                self._normalizePath(configuration["paths"]["winapi_rootdir"]) + self.cc.os.sep ) :
            #  winapi_rootdir is a relative path from the working directory
            self.winapi_rootdir = self.root_file_path + self.cc.os.sep + \
                self._normalizePath(configuration["paths"]["winapi_rootdir"]) + self.cc.os.sep
        # widget related configurations
        self.winapi_shortcut = configuration["winapi"]["search_hotkey"]
        self.winapi_load_keyword_database = configuration["winapi"]["load_keyword_database"]
        self.winapi_online_enabled = configuration["winapi"]["online_enabled"]
        self.inspection_default_semantics = configuration["inspection"]["default_semantics"]
        # semantic explorer related
        self.smtx_enum_file = self._normalizePath(self.root_file_path + self.cc.os.sep
            + configuration["semantic_explorer"]["enum_file"])
        self.smtx_semantics_file = self._normalizePath(self.root_file_path + self.cc.os.sep
            + configuration["semantic_explorer"]["semantics_file"])
        # yara related
        idascope_yara_folder = self.root_file_path + self.cc.os.sep + self.cc.os.sep.join(["idascope", "data", "yara"])
        self.yara_sig_folders = [self._normalizePath(idascope_yara_folder)]
        self.yara_sig_folders.extend(configuration["yara"]["yara_sigs"])

    def _normalizePath(self, path):
        parts = path.split(self.config_path_sep)
        return self.cc.os_path.normpath(self.cc.os.sep.join(parts))

    def __str__(self):
        """
        Convenience function.
        @return: a nice string representation for this object
        """
        return "IDAscope configuration: \n" \
            + "  root_file_path: %s\n" % self.root_file_path \
            + "  icon_file_path: %s\n" % self.icon_file_path \
            + "  semantics_file: %s\n" % self.semantics_file \
            + "  winapi_keywords_file: %s\n" % self.winapi_keywords_file \
            + "  winapi_rootdir: %s\n" % self.winapi_rootdir \
            + "  yara_sigs: %s" % self.yara_sig_folders


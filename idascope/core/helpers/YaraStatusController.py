#!/usr/bin/python
########################################################################
# Copyright (c) 2014
# Christopher Kannen <ckannen<at>uni-bonn<dot>de>
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
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
#
########################################################################


class StatusController(object):
    """ Status Controller class """

    def __init__(self):
        """ init Status Controller Object """
        self.status = ""

    def reset(self, status=""):
        self.status = status

    def findKeyword(self, content, start_pos, keyword, needed_prefix_list=[]):
        """ find keyword in given string at given position """
        # check if keyword even fits in content
        if content[start_pos:start_pos + len(keyword)] != keyword:
            return False
        # check if prefix is one of the needed ones
        if needed_prefix_list != []:
            for needed_prefix in needed_prefix_list:
                if content[start_pos - len(needed_prefix):start_pos] == needed_prefix:
                    return True
            return False
        # return True if everything is ok
        return True

    def controlStatus(self, status_condition, second_condition, new_status):
        """ if status is in the correct state and condition is true, change status """
        if (self.status == status_condition) and second_condition:
            # change status, if a new status is passed
            if (new_status != None):
                self.status = new_status
            return True
        return False

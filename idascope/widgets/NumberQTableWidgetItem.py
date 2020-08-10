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

import idascope.core.helpers.QtShim as QtShim
QTableWidgetItem = QtShim.get_QTableWidgetItem()


class NumberQTableWidgetItem(QTableWidgetItem):
    """
    A simple helper class that allows sorting by numeric values.
    """

    def __lt__(self, other):
        """
        Redefine function from QTableWidgetItem to allow sorting by numeric value instead of string value.
        @param other: another item of the same type
        @type other: I{NumberQTableWidgetItem}
        @return: (boolean) the numeric comparison of the items.
        """
        return float(self.text()) < float(other.text())

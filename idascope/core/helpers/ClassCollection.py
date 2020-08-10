#!/usr/bin/python
########################################################################
# Copyright (c) 2016
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
import os
import sys
import time
import re
from collections import deque

import idascope.core.helpers.QtShim as QtShim

from idascope.core.IdaProxy import IdaProxy
# structures
from idascope.core.structures.Segment import Segment
from idascope.core.structures.AritlogBasicBlock import AritlogBasicBlock
from idascope.core.structures.CryptoSignatureHit import CryptoSignatureHit
# helpers
import idascope.core.helpers.Misc as Misc
from idascope.core.helpers.PatternManager import PatternManager, VariablePattern, MutablePattern
from idascope.core.helpers.GraphHelper import GraphHelper
from idascope.core.helpers.ApiMatcher import ApiMatcher
from idascope.core.helpers.ApiManager import ApiManager
from idascope.core.helpers.ControlFlowBuilder import ControlFlowBuilder
from idascope.core.helpers.ControlFlowFilter import ControlFlowFilter
from idascope.core.helpers.ApiSignatureResolver import ApiSignatureResolver
# widgets
from idascope.widgets.GrowingTextEdit import GrowingTextEdit


class ClassCollection():

    def __init__(self):
        # python imports
        self.json = json
        self.os = os
        self.os_path = os.path
        self.re = re
        self.sys = sys
        self.time = time
        self.deque = deque
        # PySide / PyQt imports
        self.QtShim = QtShim
        self.QtGui = self.QtShim.get_QtGui()
        self.QtCore = self.QtShim.get_QtCore()
        self.QIcon = self.QtShim.get_QIcon()
        self.QWidget = self.QtShim.get_QWidget()
        self.QVBoxLayout = self.QtShim.get_QVBoxLayout()
        self.QHBoxLayout = self.QtShim.get_QHBoxLayout()
        self.QSplitter = self.QtShim.get_QSplitter()
        self.QStyleFactory = self.QtShim.get_QStyleFactory()
        self.QLabel = self.QtShim.get_QLabel()
        self.QTableWidget = self.QtShim.get_QTableWidget()
        self.QAbstractItemView = self.QtShim.get_QAbstractItemView()
        self.QTableWidgetItem = self.QtShim.get_QTableWidgetItem()
        self.QPushButton = self.QtShim.get_QPushButton()
        self.QScrollArea = self.QtShim.get_QScrollArea()
        self.QSizePolicy = self.QtShim.get_QSizePolicy()
        self.QLineEdit = self.QtShim.get_QLineEdit()
        self.QTextEdit = self.QtShim.get_QTextEdit()
        self.QMainWindow = self.QtShim.get_QMainWindow()
        self.QSlider = self.QtShim.get_QSlider()
        self.QCompleter = self.QtShim.get_QCompleter()
        self.QTextBrowser = self.QtShim.get_QTextBrowser()
        self.QStringListModel = self.QtShim.get_QStringListModel()
        self.QDialog = self.QtShim.get_QDialog()
        self.QGroupBox = self.QtShim.get_QGroupBox()
        self.QRadioButton = self.QtShim.get_QRadioButton()
        self.QComboBox = self.QtShim.get_QComboBox()
        self.QCheckBox = self.QtShim.get_QCheckBox()
        self.QAction = self.QtShim.get_QAction()
        self.QColor = self.QtShim.get_QColor()
        self.QBrush = self.QtShim.get_QBrush()
        self.QTreeWidget = self.QtShim.get_QTreeWidget()
        self.QTreeWidgetItem = self.QtShim.get_QTreeWidgetItem()
        self.QStyle = self.QtShim.get_QStyle()
        self.QPainter = self.QtShim.get_QPainter()
        self.QApplication = self.QtShim.get_QApplication()
        self.QStyleOptionSlider = self.QtShim.get_QStyleOptionSlider()
        self.QTabWidget = self.QtShim.get_QTabWidget()
        self.DescendingOrder = self.QtShim.get_DescendingOrder()
        # idascope imports
        self.ida_proxy = IdaProxy()
        self.Misc = Misc
        self.PatternManager = PatternManager
        self.VariablePattern = VariablePattern
        self.MutablePattern = MutablePattern
        self.GraphHelper = GraphHelper
        self.Segment = Segment
        self.AritlogBasicBlock = AritlogBasicBlock
        self.CryptoSignatureHit = CryptoSignatureHit
        self.ApiMatcher = ApiMatcher
        self.ApiManager = ApiManager
        self.ControlFlowBuilder = ControlFlowBuilder
        self.ControlFlowFilter = ControlFlowFilter
        self.ApiSignatureResolver = ApiSignatureResolver
        # delayed-loaded widgets
        self.GrowingTextEdit = GrowingTextEdit
        


#!/usr/bin/python
########################################################################
# Copyright (c) 2014
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
QMainWindow = QtShim.get_QMainWindow()

from NumberQTableWidgetItem import NumberQTableWidgetItem
from YaraRuleDialog import YaraRuleDialog


class YaraScannerWidget(QMainWindow):

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print "[|] loading YaraScannerWidget"
        # enable access to shared IDAscope modules
        self.parent = parent
        self.name = "YARA"
        self.icon = self.cc.QIcon(self.parent.config.icon_file_path + "yarascan.png")
        # This widget relies on yara scanner for resuls and scanning as well as IdaProxy for navigation
        self.ys = self.parent.yara_scanner
        self.ida_proxy = self.cc.ida_proxy
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self.YaraRuleDialog = YaraRuleDialog

        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()
        self._selected_rule = None

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # toolbar
        self._createToolbar()
        # Overview of rules and matches
        self.result_table = None
        self._createRulesWidget()
        # Details for a selected rule
        self._createResultWidget()
        # layout and fill the widget
        yara_layout = self.cc.QVBoxLayout()
        splitter = self.cc.QSplitter(self.cc.QtCore.Qt.Vertical)
        q_clean_style = self.cc.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(self.rules_widget)
        splitter.addWidget(self.result_widget)
        yara_layout.addWidget(splitter)

        self.central_widget.setLayout(yara_layout)

    def _createToolbar(self):
        """
        Creates the toolbar, containing buttons to control the widget.
        """
        self._createLoadAndScanAction()
        self.toolbar = self.addToolBar('YARA Scanner Toobar')
        self.toolbar.addAction(self.loadAndScanAction)

    def _createLoadAndScanAction(self):
        """
        Create an action for the scan button of the toolbar and connect it.
        """
        self.loadAndScanAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "search.png"),
            "(Re)load YARA Signature files and scan", self)
        self.loadAndScanAction.triggered.connect(self._onLoadAndScanButtonClicked)

    def _onLoadAndScanButtonClicked(self):
        """
        reload yara rules and scan all segments, then present results
        """
        self.ys.load_rules()
        self.ys.scan()
        self.setRulesLabel(len(self.ys.getResults()), self.ys.num_files_loaded)
        self.populateRulesTable()

################################################################################
# Rules GUI
################################################################################

    def _createRulesWidget(self):
        """
        Create the widget for the arithmetic/logic heuristic.
        """
        self.rules_widget = self.cc.QWidget()
        rules_layout = self.cc.QVBoxLayout()
        self.rules_label = self.cc.QLabel()
        self.setRulesLabel(0, 0)

        # rule visualization
        self.rules_widget = self.cc.QWidget()
        rules_layout = self.cc.QVBoxLayout()
        self._createRuleTable()

        # widget composition
        rules_layout.addWidget(self.rules_label)
        rules_layout.addWidget(self.rules_table)
        self.rules_widget.setLayout(rules_layout)

    def setRulesLabel(self, num_rules, num_files):
        self.rules_label.setText("Results for %d rules loaded from %d files" % (num_rules, num_files))

    def _createRuleTable(self):
        """
        Create the result table for displaying results yara scanning
        """
        self.rules_table = self.cc.QTableWidget()
        self.populateRulesTable()
        self.rules_table.clicked.connect(self._onRuleClicked)

    def populateRulesTable(self):
        """
        Populate the result table for yara scanning.
        Called everytime rules are loaded / scanned.
        """
        self.rules_table.clear()
        self.rules_table.setSortingEnabled(False)

        rule_results = self.ys.getResults()

        self._setRuleTableHeaderLabels()
        table_data = self._calculateRuleTableData(rule_results)
        row_count = len(table_data)

        self.rules_table.setColumnCount(len(self.rules_table_header_labels))
        self.rules_table.setHorizontalHeaderLabels(self.rules_table_header_labels)
        self.rules_table.setRowCount(row_count)
        self.rules_table.resizeRowToContents(0)

        for row, data_item in enumerate(table_data):
            for column, column_name in enumerate(self.rules_table_header_labels):
                tmp_item = self._getRuleTableItem(data_item, column)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                tmp_item.setTextAlignment(self.cc.QtCore.Qt.AlignRight)
                self.rules_table.setItem(row, column, tmp_item)
            self.rules_table.resizeRowToContents(row)

        self.rules_table.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        # size work around according to: https://stackoverflow.com/a/3445485
        self.rules_table.setVisible(False)
        self.rules_table.resizeColumnsToContents()
        self.rules_table.setVisible(True)
        # sorting
        self.rules_table.setSortingEnabled(True)
        # QtCore.Qt.SortOrder.DescendingOrder (== 1) broken in Qt5?!
        self.rules_table.sortByColumn(2, self.cc.DescendingOrder)

        if len(rule_results) > 0:
            self._selected_rule = rule_results[0]
            self.populateResultTable(rule_results[0])

    def _calculateRuleTableData(self, rule_results):
        """
        Prepare data for display in the result table for yara scan.
        @param rule_results: results of matching as performed by Yarascanner
        @type: rule_results: a list of dict, as generated by Yara
        @return: (a list of elements) where elements are temporary dictionaries prepared for display
        """
        result = []
        for rule in rule_results:
            matched_ids = [item[1] for item in rule.match_data["strings"]]
            num_unique_strings = len(set(matched_ids))
            result.append({"name": rule.rule_name,
                           "num_matched_strings": num_unique_strings,
                           "num_all_strings": len(rule.strings),
                           "match": "%s" % rule.match_data["matches"]})
        return result

    def _setRuleTableHeaderLabels(self):
        """
        Set the header labels for the yara scan result table.
        """
        self.rules_table_header_labels = ["Rule Name", "Strings Matched", "% Matched", "Match?"]

    def _getRuleTableItem(self, data_item, column_index):
        """
        Transform a data item for display in the result table
        @param data_item: the item to prepare for display
        @type data_item: a dictionary containing rule results
        @param column_index: the column to prepare the item for
        @type column_index: int
        @return: the prepared item
        """
        tmp_item = self.cc.QTableWidgetItem()
        if column_index == 0:
            tmp_item = self.cc.QTableWidgetItem(data_item["name"])
        elif column_index == 1:
            tmp_item = self.NumberQTableWidgetItem("%d" % data_item["num_matched_strings"])
        elif column_index == 2:
            if data_item["num_all_strings"] > 0:
                percentage = 100.0 * data_item["num_matched_strings"] / data_item["num_all_strings"]
                tmp_item = self.NumberQTableWidgetItem("%3.2f" % percentage)
            else:
                tmp_item = self.NumberQTableWidgetItem("0")
        elif column_index == 3:
            tmp_item = self.cc.QTableWidgetItem(data_item["match"])
        if data_item["match"] == "True":
            tmp_item.setBackground(self.cc.QBrush(self.cc.QColor(0xCC0000)))
        elif data_item["match"] == "False" and data_item["num_matched_strings"] > 0:
            tmp_item.setBackground(self.cc.QBrush(self.cc.QColor(0xFFBB00)))
        else:
            tmp_item.setBackground(self.cc.QBrush(self.cc.QColor(0x22CC00)))
        return tmp_item

    def _onRuleClicked(self, mi):
        """
        The action to perform when an entry in the arithmetic/logic table is double clicked.
        Changes IDA View either to the function or basic block, depending on the column clicked.
        """
        clicked_rule_name = self.rules_table.item(mi.row(), 0).text()
        for rule_result in self.ys.getResults():
            if rule_result.rule_name == clicked_rule_name:
                self.populateResultTable(rule_result)
                self._selected_rule = rule_result

################################################################################
# Detailed Result GUI
################################################################################

    def _createResultWidget(self):
        """
        Create the widget for the arithmetic/logic heuristic.
        """
        self.result_widget = self.cc.QWidget()
        result_layout = self.cc.QVBoxLayout()
        num_hits = 0
        num_strings = 0
        self.result_label = self.cc.QLabel("%d out of %d strings matched" % (num_hits, num_strings))
        self.rule_display_icon = self.cc.QIcon(self.parent.config.icon_file_path + "winapi.png")

        # rule visualization
        self.result_widget = self.cc.QWidget()
        result_layout = self.cc.QVBoxLayout()
        self._createResultTable()
        self._createResultInfoButton()

        self.result_info_widget = self.cc.QWidget()
        result_info_layout = self.cc.QHBoxLayout()
        result_info_layout.addWidget(self.result_info_button)
        result_info_layout.addWidget(self.result_label)
        result_info_layout.addStretch(1)
        self.result_info_widget.setLayout(result_info_layout)

        # widget composition
        result_layout.addWidget(self.result_info_widget)
        result_layout.addWidget(self.result_table)
        self.result_widget.setLayout(result_layout)

    def _createResultInfoButton(self):
        """
        Create a back button to allow easier browsing
        """
        self.result_info_button = self.cc.QPushButton(self.rule_display_icon, "", self)
        self.result_info_button.setToolTip("Show full rule")
        self.result_info_button.resize(self.result_info_button.sizeHint())
        self.result_info_button.setEnabled(True)
        self.result_info_button.clicked.connect(self._onResultInfoButtonClicked)

    def _createResultTable(self):
        """
        Create the result table for displaying results yara scanning
        """
        self.result_table = self.cc.QTableWidget()
        self.populateResultTable(None)
        self.result_table.doubleClicked.connect(self._onResultDoubleClicked)

    def populateResultTable(self, rule_result):
        """
        Populate the result table for yara scanning.
        Called everytime rules are loaded / scanned.
        """
        self.result_table.clear()
        self.result_table.setSortingEnabled(False)

        self._setResultTableHeaderLabels()
        table_data = self._calculateResultTableData(rule_result)
        row_count = len(table_data)
        matched_str = set([])
        all_str = set([])
        for data_item in table_data:
            if data_item[0]:
                matched_str.update([data_item[2]])
            all_str.update([data_item[2]])
        rule_label = ""
        if rule_result:
            rule_label = "%d out of %d strings matched (%s)" % (len(matched_str), len(all_str), rule_result.rule_name)
        else:
            rule_label = "No rule selected."
        self.result_label.setText(rule_label)

        self.result_table.setColumnCount(len(self.result_table_header_labels))
        self.result_table.setHorizontalHeaderLabels(self.result_table_header_labels)
        self.result_table.setRowCount(row_count)
        self.result_table.resizeRowToContents(0)

        for row, data_item in enumerate(table_data):
            for column, column_name in enumerate(self.result_table_header_labels):
                tmp_item = self._getResultTableItem(data_item, column)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                tmp_item.setTextAlignment(self.cc.QtCore.Qt.AlignRight)
                self.result_table.setItem(row, column, tmp_item)
            self.result_table.resizeRowToContents(row)

        self.result_table.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.result_table.resizeColumnsToContents()
        self.result_table.setSortingEnabled(True)

    def _setResultTableHeaderLabels(self):
        """
        Set the header labels for the yara scan result table.
        """
        self.result_table_header_labels = ["Address / Type", "String ID", "Value"]

    def _calculateResultTableData(self, rule_result):
        """
        Prepare data for display in the result table for yara scan.
        @param rule_results: results of matching as performed by Yarascanner
        @type: rule_results: a list of dict, as generated by Yara
        @return: (a list of elements) where elements are temporary dictionaries prepared for display
        """
        if not rule_result:
            return []
        result = []
        for string in rule_result.match_data["strings"]:
            res_tuple = (True, string[0], string[1], string[2])
            result.append(res_tuple)
        matched_strings = [string[2] for string in result]
        for string in rule_result.strings:
            if string[1] not in matched_strings:
                res_tuple = (False, string[0], string[1], string[2])
                result.append(res_tuple)
        return result

    def _getResultTableItem(self, data_item, column_index):
        """
        Transform a data item for display in the result table
        @param data_item: the item to prepare for display
        @type data_item: a dictionary containing rule results
        @param column_index: the column to prepare the item for
        @type column_index: int
        @return: the prepared item
        """
        tmp_item = self.cc.QTableWidgetItem()
        if column_index == 0:
            if data_item[0]:
                tmp_item = self.cc.QTableWidgetItem("0x%x" % data_item[1])
            else:
                tmp_item = self.cc.QTableWidgetItem("%s" % data_item[1])
        elif column_index == 1:
            tmp_item = self.cc.QTableWidgetItem("%s" % data_item[2])
        elif column_index == 2:
            tmp_item = self.cc.QTableWidgetItem("%s" % data_item[3])
        if data_item[0]:
            tmp_item.setBackground(self.cc.QBrush(self.cc.QColor(0xCC0000)))
        else:
            tmp_item.setBackground(self.cc.QBrush(self.cc.QColor(0x22CC00)))
        return tmp_item

    def _onResultDoubleClicked(self, mi):
        """
        The action to perform when an entry in the arithmetic/logic table is double clicked.
        Changes IDA View either to the function or basic block, depending on the column clicked.
        """
        clicked_address = self.result_table.item(mi.row(), 0).text()
        try:
            self.ida_proxy.Jump(int(clicked_address, 16))
        except ValueError:
            pass

    def _onResultInfoButtonClicked(self):
        dialog = self.YaraRuleDialog(self, self._selected_rule)
        dialog.exec_()

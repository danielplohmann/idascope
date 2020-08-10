#!/usr/bin/python
########################################################################
# Copyright (c) 2014
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Laura Guevara
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
from FunctionFilterDialog import FunctionFilterDialog


class SemanticExplorerWidget(QMainWindow):
    """
    This widget is the front-end for the semantic inspection.
    """

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print "[|] loading SemanticExplorerWidget"
        # enable access to shared IDAscope modules
        self.parent = parent
        self.name = "Semantics"
        self.icon = self.cc.QIcon(self.parent.config.icon_file_path + "semantics.png")
        self.winapi_icon = self.cc.QIcon(self.parent.config.icon_file_path + "winapi.png")
        # This widget relies on the semantic identifier and uses some functions via IDA proxy
        self.smtx = self.parent.semantic_explorer
        self.ida_proxy = self.cc.ida_proxy
        # references to Qt-specific modules
        self.QtGui = self.cc.QtGui
        self.QtCore = self.cc.QtCore
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self.FunctionFilterDialog = FunctionFilterDialog
        self.isUsingCategories = True
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()
        # local fields
        self.activeApiName = ""

    def _createGui(self):
        """
        Create the main GUI with its components.
        """
        self.api_filter_label = self.cc.QLabel("Filter")
        self.arguments_label = self.cc.QLabel("Arguments of the selected API call: <none>")

        self.api_filter_lineedit = self.cc.QLineEdit()
        self.api_filter_lineedit.textChanged.connect(self._filterMatchesTree)

        self._createToolbar()

        self._createSemanticMatchesTree()
        self._createArgumentsTable()

        # layout and fill the widget
        semantics_layout = self.cc.QVBoxLayout()

        hits_info_widget = self.cc.QWidget()
        hits_info_layout = self.cc.QHBoxLayout()
        hits_info_layout.addWidget(self.api_filter_label)
        hits_info_layout.addWidget(self.api_filter_lineedit)
        hits_info_widget.setLayout(hits_info_layout)

        hits_widget = self.cc.QWidget()
        upper_layout = self.cc.QVBoxLayout()
        upper_layout.addWidget(hits_info_widget)
        upper_layout.addWidget(self.matches_tree_widget)
        hits_widget.setLayout(upper_layout)

        api_arguments_widget = self.cc.QWidget()
        api_arguments_layout = self.cc.QHBoxLayout()
        api_arguments_layout.addWidget(self.arguments_table)
        api_arguments_widget.setLayout(api_arguments_layout)

        self.winapi_button = self.cc.QPushButton(self.winapi_icon, "", self)
        self.winapi_button.setToolTip("Look up this API in WinAPI view.")
        self.winapi_button.resize(self.winapi_button.sizeHint())
        self.winapi_button.clicked.connect(self._onWinApiButtonClicked)

        selected_api_widget = self.cc.QWidget()
        selected_api_layout = self.cc.QHBoxLayout()
        selected_api_layout.addWidget(self.arguments_label)
        selected_api_layout.addWidget(self.winapi_button)
        selected_api_layout.addStretch(1)
        selected_api_widget.setLayout(selected_api_layout)

        lower_tables_widget = self.cc.QWidget()
        lower_tables_layout = self.cc.QVBoxLayout()
        lower_tables_layout.addWidget(selected_api_widget)
        lower_tables_layout.addWidget(api_arguments_widget)
        lower_tables_widget.setLayout(lower_tables_layout)

        splitter = self.cc.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = self.cc.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(hits_widget)
        splitter.addWidget(lower_tables_widget)
        semantics_layout.addWidget(splitter)

        self.central_widget.setLayout(semantics_layout)

        self.update()

    def _createToolbar(self):
        """
        Create the toolbar, containing some of the actions that can be performed with this widget.
        """
        self._createRefreshAction()
        self._createCategorizeAction()

        self.toolbar = self.addToolBar('Semantic Explorer Toobar')
        self.toolbar.addAction(self.refreshAction)
        self.toolbar.addAction(self.categorizeAction)

    def _createRefreshAction(self):
        """
        Create the refresh action for the toolbar. On activiation, it triggers a scan of I{SemanticExplorer} and
        updates the GUI.
        """
        self.refreshAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "scan.png"), "Refresh the "
            + "view by scanningagain.", self)
        self.refreshAction.triggered.connect(self._onRefreshButtonClicked)

    def _createCategorizeAction(self):
        """
        Create the toggle categories action for the toolbar. On activiation, it triggers a change in the display,
        showing the matches grouped by categories or all at once.
        """
        self.categorizeAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "tags.png"), "Show matches by categories.", self)
        self.categorizeAction.triggered.connect(self._onCategorizeButtonClicked)

    def _createSemanticMatchesTree(self):
        """
        Create the tree in the top view used for showing all functions covered by scanning for semantic information.
        """
        self.matches_tree_widget = self.cc.QWidget()
        matches_tree_layout = self.cc.QVBoxLayout()
        self.matches_tree = self.cc.QTreeWidget()
        self.matches_tree.setColumnCount(1)
        self.matches_tree.setHeaderLabels(["Semantics"])
        self.matches_tree.itemDoubleClicked.connect(self._onMatchesTreeItemDoubleClicked)
        self.matches_tree.itemClicked.connect(self._onMatchesTreeItemClicked)
        matches_tree_layout.addWidget(self.matches_tree)
        self.matches_tree_widget.setLayout(matches_tree_layout)

    def _createArgumentsTable(self):
        """
        Create the bottom table used for showing all arguments for the selected API call
        """
        self.arguments_table = self.cc.QTableWidget()
        self.arguments_table.setSortingEnabled(False)

################################################################################
# Rendering and state keeping
################################################################################

    def update(self):
        self.populateMatchesTree()

    def populateMatchesTree(self, matchFilter=""):
        """
        populate the TreeWidget for display of the semantic scanning results.
        """
        num_matched_semantics = 0
        self.matches_tree.clear()
        self.matches_tree.setSortingEnabled(False)

        self.qtreewidgetitems_to_addresses = {}
        self.qtreewidgetitems_to_arguments = {}

        if self.isUsingCategories:
            categorized_matches = self.smtx.getCategorizedMatches()
            for category in categorized_matches.keys():
                root = self.cc.QTreeWidgetItem(self.matches_tree)
                for match in categorized_matches[category]:
                    num_matched_semantics += self.addMatchToTree(match, matchFilter, root)
                if category == "":
                    category = "No Category"
                root.setText(0, "%s (%d)" % (category, len(categorized_matches[category])))
        else:
            semantic_matches = self.smtx.getSemanticMatches()
            for match in semantic_matches:
                num_matched_semantics += self.addMatchToTree(match, matchFilter, self.matches_tree)
        self.matches_tree.setSortingEnabled(True)
        if matchFilter:
            self.matches_tree.expandAll()
        else:
            self.matches_tree.collapseAll()
        self.matches_tree.setHeaderLabels(["Semantics matched: %d" % num_matched_semantics, "Function"])

    def addMatchToTree(self, match, matchFilter, tree_node):
        tag = match["tag"].lower()
        api_names = [api["api_name"].lower() for api in match["hit"]["apis"]]
        is_matching_filter = matchFilter.lower() in tag or [api_name for api_name in api_names if matchFilter.lower() in api_name]
        if not matchFilter or is_matching_filter:
            root = self.cc.QTreeWidgetItem(tree_node)
            root.setText(0, "%s (0x%x)" % (match["tag"],
                                                match["hit"]["start_addr"]))
            root.setText(1, "%s" % (self.ida_proxy.GetFunctionName(match["hit"]["start_addr"])))
            if matchFilter and matchFilter.lower() in match["tag"].lower():
                root.setForeground(0, self.cc.QBrush(self.cc.QColor(0x0000FF)))
            for api in reversed(match["hit"]["apis"]):
                api_information = self.cc.QTreeWidgetItem(root)
                api_information.setText(0, "0x%x %s" % (api["addr"], api["api_name"]))
                api_information.setText(1, "%s" % (self.ida_proxy.GetFunctionName(api["addr"])))
                if matchFilter and matchFilter.lower() in api["api_name"].lower():
                    api_information.setForeground(0, self.cc.QBrush(self.cc.QColor(0xFF0000)))
                self.qtreewidgetitems_to_addresses[api_information] = api["addr"]
                arg_details = {"api_name": api["api_name"],
                               "api_args": api["arguments"]}
                self.qtreewidgetitems_to_arguments[api_information] = arg_details
        return 1 if not matchFilter or is_matching_filter else 0

    def populateArgumentsTable(self, arguments):
        """
        Populate the API call argument table based on the selected function in the tree view.
        """
        self.arguments_table_header_labels = ["Type", "Name", "Value"]
        self.arguments_table.clear()
        self.arguments_table.setColumnCount(len(self.arguments_table_header_labels))
        self.arguments_table.setHorizontalHeaderLabels(self.arguments_table_header_labels)
        self.arguments_table.setRowCount(0)

        if arguments:
            self.arguments_table.setRowCount(len(arguments))
            for row, argument in enumerate(arguments):
                for column, column_name in enumerate(self.arguments_table_header_labels):
                    if column == 0:
                        tmp_item = self.cc.QTableWidgetItem("%s" % (argument["arg_type"] if "arg_type" in argument else ""))
                    elif column == 1:
                        tmp_item = self.cc.QTableWidgetItem("%s" % argument["arg_name"])
                    elif column == 2:
                        tmp_item = self.cc.QTableWidgetItem("%s" % argument["arg_value"])
                    tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                    self.arguments_table.setItem(row, column, tmp_item)
                self.arguments_table.resizeRowToContents(row)
            self.arguments_table.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
            self.arguments_table.resizeColumnsToContents()

    def _resetLowerTables(self):
        self.arguments_table.clear()
        self.arguments_table.setRowCount(0)
        self.arguments_table_header_labels = ["Address", "API", "Tag"]
        self.arguments_table.setColumnCount(len(self.arguments_table_header_labels))
        self.arguments_table.setHorizontalHeaderLabels(self.arguments_table_header_labels)

    def updateArgumentsLabel(self, api_name):
        self.arguments_label.setText("Arguments of the selected API call: %s" % api_name)

################################################################################
# Button actions
################################################################################

    def _onRefreshButtonClicked(self):
        """
        Action for refreshing the window data by performing another scan of I{SemanticExplorer}.
        """
        self.smtx.analyze()
        self.updateArgumentsLabel("<none>")
        self._resetLowerTables()
        self.update()

    def _onCategorizeButtonClicked(self):
        """
        Action for switching display from categorized view to unwinded view
        """
        self.isUsingCategories = not self.isUsingCategories
        self.update()

    def _onWinApiButtonClicked(self):
        """
        Action for looking up the last selected API with WinAPI view.
        """
        if self.activeApiName:
            for widget in self.parent.idascope_widgets:
                if widget.name == "WinAPI":
                    widget.navigate(self.activeApiName)
                    self.parent.setTabFocus("WinAPI")

    def _onParameterDoubleClicked(self, mi):
        """
        If a parameter in the parameter table is doubleclicked, IDA View is located to the corresponding address.
        """
        # clicked_function_address = self.parameter_table.item(mi.row(), 0).text()
        # self.ida_proxy.Jump(int(clicked_function_address, 16))
        return

    def _onMatchesTreeItemDoubleClicked(self, item, column):
        """
        The action to perform when an entry in the signature TreeWidget is double clicked.
        Changes IDA View either to location clicked.
        """
        if item in self.qtreewidgetitems_to_addresses:
            self.ida_proxy.Jump(self.qtreewidgetitems_to_addresses[item])
        return

    def _onMatchesTreeItemClicked(self, item, column):
        """
        The action to perform when an entry in the signature TreeWidget is double clicked.
        Changes IDA View either to location clicked.
        """
        if item in self.qtreewidgetitems_to_arguments:
            api_name = self.qtreewidgetitems_to_arguments[item]["api_name"]
            api_args = self.qtreewidgetitems_to_arguments[item]["api_args"]
            self.updateArgumentsLabel(api_name)
            self.activeApiName = api_name
            self.populateArgumentsTable(api_args)
        return

    def _filterMatchesTree(self):
        self.populateMatchesTree(self.api_filter_lineedit.text())


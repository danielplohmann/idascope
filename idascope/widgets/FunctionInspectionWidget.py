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
QMainWindow = QtShim.get_QMainWindow()

from NumberQTableWidgetItem import NumberQTableWidgetItem
from FunctionFilterDialog import FunctionFilterDialog


class FunctionInspectionWidget(QMainWindow):
    """
    This widget is the front-end for the semantic inspection.
    """

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print "[|] loading FunctionInspectionWidget"
        # enable access to shared IDAscope modules
        self.parent = parent
        self.name = "Functions"
        self.icon = self.cc.QIcon(self.parent.config.icon_file_path + "inspection.png")
        # This widget relies on the semantic identifier and uses some functions via IDA proxy
        self.si = self.parent.semantic_identifier
        self.context_filter = self.si.createFunctionContextFilter()
        self.dh = self.parent.documentation_helper
        self.ida_proxy = self.cc.ida_proxy
        # references to Qt-specific modules
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self.FunctionFilterDialog = FunctionFilterDialog
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()

    def _createGui(self):
        """
        Create the main GUI with its components.
        """
        self.funcs_label = self.cc.QLabel("Functions of Interest (0/0)")
        self.calls_label = self.cc.QLabel("Selected function contains the following API references with parameters:")

        self._createToolbar()

        self._createFunctionsTable()
        self._createCallsTable()
        self._createParameterTable()

        # layout and fill the widget
        semantics_layout = self.cc.QVBoxLayout()

        function_info_widget = self.cc.QWidget()
        function_info_layout = self.cc.QHBoxLayout()
        function_info_layout.addWidget(self.funcs_label)
        function_info_widget.setLayout(function_info_layout)

        upper_table_widget = self.cc.QWidget()
        upper_table_layout = self.cc.QVBoxLayout()
        upper_table_layout.addWidget(function_info_widget)
        upper_table_layout.addWidget(self.funcs_table)
        upper_table_widget.setLayout(upper_table_layout)

        calls_params_widget = self.cc.QWidget()
        calls_params_layout = self.cc.QHBoxLayout()
        calls_params_layout.addWidget(self.calls_table)
        calls_params_layout.addWidget(self.parameter_table)
        calls_params_widget.setLayout(calls_params_layout)

        lower_tables_widget = self.cc.QWidget()
        lower_tables_layout = self.cc.QVBoxLayout()
        lower_tables_layout.addWidget(self.calls_label)
        lower_tables_layout.addWidget(calls_params_widget)
        lower_tables_widget.setLayout(lower_tables_layout)

        splitter = self.cc.QSplitter(self.cc.QtCore.Qt.Vertical)
        q_clean_style = self.cc.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(upper_table_widget)
        splitter.addWidget(lower_tables_widget)
        semantics_layout.addWidget(splitter)

        self.central_widget.setLayout(semantics_layout)

        self.update()

    def _createToolbar(self):
        """
        Create the toolbar, containing some of the actions that can be performed with this widget.
        """
        self._createRefreshAction()
        self._createDeepScanAction()
        self._createRenameAction()
        self._createColoringAction()
        self._createFixUnknownCodeWithProloguesAction()
        self._createFixAllUnknownCodeAction()
        self._createRenameWrappersAction()
        self._createFilterAction()
        self._createSemanticsChooserAction()

        self.toolbar = self.addToolBar('Function Inspection Toobar')
        self.toolbar.addAction(self.refreshAction)
        self.toolbar.addAction(self.deepScanAction)
        self.toolbar.addAction(self.annotateAction)
        self.toolbar.addAction(self.toggleColorAction)
        self.toolbar.addAction(self.fixUnknownCodeWithProloguesAction)
        self.toolbar.addAction(self.fixAllUnknownCodeAction)
        self.toolbar.addAction(self.renameWrappersAction)
        self.toolbar.addAction(self.filterAction)
        self.toolbar.addWidget(self.semanticsChooserAction)

    def _createRefreshAction(self):
        """
        Create the refresh action for the toolbar. On activiation, it triggers a scan of I{SemanticIdentifier} and
        updates the GUI.
        """
        self.refreshAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "scan.png"), "Refresh the " \
            + "view by scanning all named references again.", self)
        self.refreshAction.triggered.connect(self._onRefreshButtonClicked)

    def _createDeepScanAction(self):
        """
        Create the deep scan action for the toolbar. On activiation, it triggers a deep scan of I{SemanticIdentifier}
        andupdates the GUI.
        """
        self.deepScanAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "scandeep.png"), "Refresh the " \
            + "view by deep scanning all code.", self)
        self.deepScanAction.triggered.connect(self._onDeepScanButtonClicked)

    def _createRenameAction(self):
        """
        Create the action which performs renaming of the function names in the IDB that are covered by the scan of
        the I{SemanticIdentifier}.
        """
        self.annotateAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "tags.png"), "Rename functions " \
            + "according to the identified tags.", self)
        self.annotateAction.triggered.connect(self._onRenameButtonClicked)

    def _createColoringAction(self):
        """
        Create the action which cycles through the semantic code coloring modes via I{DocumentationHelper}.
        """
        self.toggleColorAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "colors.png"), \
            "Toggle semantic coloring.", self)
        self.toggleColorAction.triggered.connect(self._onColoringButtonClicked)

    def _createFixUnknownCodeWithProloguesAction(self):
        """
        Create the action which fixes unknown code to functions via I{DocumentationHelper}.
        """
        self.fixUnknownCodeWithProloguesAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "fix.png"), \
            "Fix unknown code that has a well-known function prologue to functions.", self)
        self.fixUnknownCodeWithProloguesAction.triggered.connect(self._onFixUnknownCodeWithProloguesButtonClicked)

    def _createFixAllUnknownCodeAction(self):
        """
        Create the action which fixes unknown code to functions via I{DocumentationHelper}.
        """
        self.fixAllUnknownCodeAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "fix_all.png"), \
            "Fix all unknown code to functions.", self)
        self.fixAllUnknownCodeAction.triggered.connect(self._onFixAllUnknownCodeButtonClicked)

    def _createFixUnknownCodeAction(self):
        """
        Create the action which fixes unknown code to functions via I{DocumentationHelper}.
        """
        self.fixUnknownCodeAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "fix.png"), \
            "Fix unknown code to functions", self)
        self.fixUnknownCodeAction.triggered.connect(self._onFixUnknownCodeButtonClicked)

    def _createRenameWrappersAction(self):
        """
        Create the action which fixes unknown code to functions via I{DocumentationHelper}.
        """
        self.renameWrappersAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "unwrap.png"), \
            "Rename potential wrapper functions", self)
        self.renameWrappersAction.triggered.connect(self._onRenameWrappersButtonClicked)

    def _createFilterAction(self):
        """
        Create the action which fixes unknown code to functions via I{DocumentationHelper}.
        """
        self.filterAction = self.cc.QAction(self.cc.QIcon(self.parent.config.icon_file_path + "filter.png"), \
            "Adjust filter settings", self)
        self.filterAction.triggered.connect(self._onFilterButtonClicked)

    def _createSemanticsChooserAction(self):
        """
        Create the action which fixes unknown code to functions via I{DocumentationHelper}.
        """
        self.semanticsChooserAction = self.cc.QComboBox()
        self.semanticsChooserAction.addItems(self.si.getSemanticsNames())
        if self.si.getActiveSemanticsName() in self.si.getSemanticsNames():
            self.semanticsChooserAction.setCurrentIndex(self.si.getSemanticsNames().index(self.si.getActiveSemanticsName()))
        self.semanticsChooserAction.currentIndexChanged.connect(self.onSemanticsChosen)

    def _createFunctionsTable(self):
        """
        Create the top table used for showing all functions covered by scanning for semantic information.
        """
        self.funcs_table = self.cc.QTableWidget()
        self.funcs_table.clicked.connect(self._onFunctionClicked)
        self.funcs_table.doubleClicked.connect(self._onFunctionDoubleClicked)

    def _createCallsTable(self):
        """
        Create the bottom left table used for showing all identified API calls that are contained in the function
        selected in the function table.
        """
        self.calls_table = self.cc.QTableWidget()
        self.calls_table.clicked.connect(self._onCallClicked)
        self.calls_table.doubleClicked.connect(self._onCallDoubleClicked)

    def _createParameterTable(self):
        """
        Create the bottom right table used for showing all parameters for the API call selected in the calls table.
        """
        self.parameter_table = self.cc.QTableWidget()
        self.parameter_table.doubleClicked.connect(self._onParameterDoubleClicked)

################################################################################
# Rendering and state keeping
################################################################################

    def update(self):
        self.context_filter = self.si.createFunctionContextFilter()
        self.populateFunctionTable()
        self.updateFunctionsLabel()
        self.semanticsChooserAction.setEditText(self.si.getActiveSemanticsName())

    def populateFunctionTable(self):
        """
        Populate the function table with information from the last scan of I{SemanticIdentifier}.
        """
        self.funcs_table.setSortingEnabled(False)
        self.funcs_header_labels = ["Address", "Name"]
        for heading in self.context_filter.generateColumnHeadings():
            self.funcs_header_labels.append(heading)
        self.funcs_table.clear()
        self.funcs_table.setColumnCount(len(self.funcs_header_labels))
        self.funcs_table.setHorizontalHeaderLabels(self.funcs_header_labels)
        # Identify number of table entries and prepare addresses to display
        function_addresses = self.si.getFunctionAddresses(self.context_filter)
        if self.ida_proxy.BAD_ADDR in function_addresses:
            self.funcs_table.setRowCount(len(function_addresses) - 1)
        else:
            self.funcs_table.setRowCount(len(function_addresses))
        self.funcs_table.resizeRowToContents(0)

        for row, function_address in enumerate(function_addresses):
            # we don't want to render entries in the table that appear because analysis failed on broken code.
            if function_address == self.ida_proxy.BAD_ADDR:
                continue
            for column, column_name in enumerate(self.funcs_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.cc.QTableWidgetItem("0x%x" % function_address)
                elif column == 1:
                    tmp_item = self.cc.QTableWidgetItem(self.ida_proxy.GetFunctionName(function_address))
                else:
                    query = self.context_filter.getQueryForHeading(column_name)
                    field_count = self.si.getFieldCountForFunctionAddress(query, function_address)
                    tmp_item = self.NumberQTableWidgetItem("%d" % field_count)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.funcs_table.setItem(row, column, tmp_item)
            self.funcs_table.resizeRowToContents(row)
        self.funcs_table.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.funcs_table.resizeColumnsToContents()
        self.funcs_table.setSortingEnabled(True)
        self.updateFunctionsLabel()

    def populateCallsTable(self, function_address):
        """
        Populate the calls table based on the selected function in the functions table.
        """
        self.calls_table.setSortingEnabled(False)
        self.calls_header_labels = ["Address", "API", "Tag"]
        self.calls_table.clear()
        self.calls_table.setColumnCount(len(self.calls_header_labels))
        self.calls_table.setHorizontalHeaderLabels(self.calls_header_labels)

        if function_address is not None:
            tagged_call_contexts = self.si.getTaggedApisForFunctionAddress(function_address)
            self.calls_table.setRowCount(len(tagged_call_contexts))
            for row, tagged_call_ctx in enumerate(tagged_call_contexts):
                for column, column_name in enumerate(self.calls_header_labels):
                    if column == 0:
                        tmp_item = self.cc.QTableWidgetItem("0x%x" % tagged_call_ctx.address_of_call)
                    elif column == 1:
                        tmp_item = self.cc.QTableWidgetItem(tagged_call_ctx.called_function_name)
                    elif column == 2:
                        tmp_item = self.cc.QTableWidgetItem(tagged_call_ctx.tag)
                    tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                    self.calls_table.setItem(row, column, tmp_item)
                self.calls_table.resizeRowToContents(row)
            self.calls_table.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
            self.calls_table.resizeColumnsToContents()
            self.calls_table.setSortingEnabled(True)

    def populateParameterTable(self, call_address):
        """
        Populate the parameter table based on the selected API call in the calls table.
        """
        self.parameter_table.setSortingEnabled(False)
        self.parameter_header_labels = ["Address", "Type", "Name", "Value"]
        self.parameter_table.clear()
        self.parameter_table.setColumnCount(len(self.parameter_header_labels))
        self.parameter_table.setHorizontalHeaderLabels(self.parameter_header_labels)

        if call_address is not None:
            parameter_contexts = self.si.getParametersForCallAddress(call_address)
            self.parameter_table.setRowCount(len(parameter_contexts))
            for row, parameter_ctx in enumerate(parameter_contexts):
                for column, column_name in enumerate(self.parameter_header_labels):
                    if column == 0:
                        tmp_item = self.cc.QTableWidgetItem(parameter_ctx.getRenderedPushAddress())
                    elif column == 1:
                        tmp_item = self.cc.QTableWidgetItem(parameter_ctx.parameter_type)
                    elif column == 2:
                        tmp_item = self.cc.QTableWidgetItem(parameter_ctx.parameter_name)
                    elif column == 3:
                        tmp_item = self.cc.QTableWidgetItem(parameter_ctx.getRenderedValue())
                    tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                    self.parameter_table.setItem(row, column, tmp_item)
                self.parameter_table.resizeRowToContents(row)
            self.parameter_table.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
            self.parameter_table.resizeColumnsToContents()
            self.parameter_table.setSortingEnabled(True)

    def _resetLowerTables(self):
        self.calls_table.clear()
        self.calls_table.setRowCount(0)
        self.calls_header_labels = ["Address", "API", "Tag"]
        self.calls_table.setColumnCount(len(self.calls_header_labels))
        self.calls_table.setHorizontalHeaderLabels(self.calls_header_labels)
        self.parameter_table.clear()
        self.parameter_table.setRowCount(0)
        self.parameter_header_labels = ["Address", "Type", "Name", "Value"]
        self.parameter_table.setColumnCount(len(self.parameter_header_labels))
        self.parameter_table.setHorizontalHeaderLabels(self.parameter_header_labels)

    def updateFunctionsLabel(self):
        displayed_function_addresses = self.si.getFunctionAddresses(self.context_filter)
        num_displayed_functions = len(displayed_function_addresses)
        if self.ida_proxy.BAD_ADDR in displayed_function_addresses:
            num_displayed_functions -= 1
        self.funcs_label.setText("Functions: %d - Tagged: %d - Displayed: %d" %
            (self.si.calculateNumberOfFunctions(), self.si.calculateNumberOfTaggedFunctions(), num_displayed_functions))

################################################################################
# Button actions
################################################################################

    def _onRenameButtonClicked(self):
        """
        Action for renaming functions when the rename action from the toolbar is activated.
        """
        self.si.renameFunctions()
        self._onRefreshButtonClicked()

    def _onRefreshButtonClicked(self):
        """
        Action for refreshing the window data by performing another scan of I{SemanticIdentifier}.
        """
        self.si.scanByReferences()
        self.context_filter = self.si.createFunctionContextFilter()
        self.populateFunctionTable()
        self._resetLowerTables()

    def _onDeepScanButtonClicked(self):
        """
        Action for refreshing the window data by performing a deep scan of I{SemanticIdentifier}.
        """
        self.si.scan()
        self.context_filter = self.si.createFunctionContextFilter()
        self.populateFunctionTable()
        self._resetLowerTables()

    def _onColoringButtonClicked(self):
        """
        Action for performing semantic coloring of instructions.
        """
        self.dh.colorize(self.si.getLastScanResult())

    def _onFixUnknownCodeWithProloguesButtonClicked(self):
        """
        Action for fixing unknown parts of code (red in address bar) to functions.
        """
        self.dh.convertAnyProloguesToFunctions()

    def _onFixAllUnknownCodeButtonClicked(self):
        """
        Action for fixing unknown parts of code (red in address bar) to functions.
        """
        self.dh.convertNonFunctionCode()

    def _onRenameWrappersButtonClicked(self):
        """
        Action for renaming potential wrapper functions to the wrapped API if they have a dummy name.
        """
        self.si.renamePotentialWrapperFunctions()

    def _onFilterButtonClicked(self):
        """
        Action for renaming potential wrapper functions to the wrapped API if they have a dummy name.
        """
        dialog = self.FunctionFilterDialog(self, self.context_filter)
        dialog.exec_()
        self.context_filter = dialog.getAdjustedFunctionFilter()
        self.populateFunctionTable()

    def onSemanticsChosen(self, index):
        """
        Action for changing the semantics profile used for identifying API usage.
        """
        self.si._setSemantics(self.semanticsChooserAction.itemText(index))
        self.update()

    def _onFunctionClicked(self, mi):
        """
        If a function in the functions table is clicked, the view of the calls and parameter table are updated.
        """
        clicked_function_address = int(self.funcs_table.item(mi.row(), \
            0).text(), 16)
        self.populateCallsTable(clicked_function_address)

    def _onFunctionDoubleClicked(self, mi):
        """
        If a function in the functions table is doubleclicked, IDA View is located to the corresponding address.
        """
        clicked_function_address = self.funcs_table.item(mi.row(), 0).text()
        self.ida_proxy.Jump(int(clicked_function_address, 16))

    def _onCallClicked(self, mi):
        """
        If an API call in the calls table is clicked, the view of the parameter table is updated.
        """
        clicked_function_address = int(self.calls_table.item(mi.row(), \
            0).text(), 16)
        self.populateParameterTable(clicked_function_address)

    def _onCallDoubleClicked(self, mi):
        """
        If an API in the calls table is doubleclicked, IDA View is located to the corresponding address.
        """
        if mi.column() == 1:
            for widget in self.parent.idascope_widgets:
                if widget.name == "WinAPI":
                    widget.navigate(self.calls_table.item(mi.row(), mi.column()).text())
                    self.parent.setTabFocus("WinAPI")
        else:
            clicked_function_address = self.calls_table.item(mi.row(), 0).text()
            self.ida_proxy.Jump(int(clicked_function_address, 16))

    def _onParameterDoubleClicked(self, mi):
        """
        If a parameter in the parameter table is doubleclicked, IDA View is located to the corresponding address.
        """
        clicked_function_address = self.parameter_table.item(mi.row(), 0).text()
        self.ida_proxy.Jump(int(clicked_function_address, 16))

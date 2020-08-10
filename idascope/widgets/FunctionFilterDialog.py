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
QDialog = QtShim.get_QDialog()


class FunctionFilterDialog(QDialog):

    def __init__(self, parent, context_filter):
        self.cc = parent.cc
        self.cc.QDialog.__init__(self, parent)
        self.context_filter = context_filter
        # create GUI elements
        self._createGroupingModeBox()
        self._createTagsBox()
        self._createGroupsBox()
        self._createGroupsTagsWidget()
        self._createAdditionalsBox()
        self._createDecisionWidget()
        self._createButtons()
        # glue everything together
        dialog_layout = self.cc.QVBoxLayout()
        dialog_layout.addWidget(self.decision_widget)
        dialog_layout.addLayout(self.button_layout)
        self.setLayout(dialog_layout)
        self.setWindowTitle(self.tr("Filter Function Results"))
        self._updateGroupingModeDisplay()

    def _createGroupingModeBox(self):
        self.grouping_mode_box = self.cc.QGroupBox("Display granularity")
        self.grouping_mode_all = self.cc.QRadioButton("Show all")
        self.grouping_mode_all.clicked.connect(self._updateGroupingModeDisplay)
        if self.context_filter.display_all:
            self.grouping_mode_all.setChecked(True)
        self.grouping_mode_tags = self.cc.QRadioButton("Show individual tags")
        self.grouping_mode_tags.clicked.connect(self._updateGroupingModeDisplay)
        if self.context_filter.display_tags:
            self.grouping_mode_tags.setChecked(True)
        self.grouping_mode_grouped = self.cc.QRadioButton("Group by semantics")
        self.grouping_mode_grouped.clicked.connect(self._updateGroupingModeDisplay)
        if self.context_filter.display_groups:
            self.grouping_mode_grouped.setChecked(True)
        self.grouping_mode_hbox = self.cc.QHBoxLayout()
        self.grouping_mode_hbox.addWidget(self.grouping_mode_all)
        self.grouping_mode_hbox.addWidget(self.grouping_mode_tags)
        self.grouping_mode_hbox.addWidget(self.grouping_mode_grouped)
        self.grouping_mode_hbox.addStretch(1)
        self.grouping_mode_box.setLayout(self.grouping_mode_hbox)

    def _createTagsBox(self):
        height_split = 6
        self.tags_box = self.cc.QGroupBox("Display Tags")
        self.tags_hbox = self.cc.QHBoxLayout()
        self.tags_map = {}
        current_col_vbox = self.cc.QVBoxLayout()
        for index, tag in enumerate(self.context_filter.tags):
            tags_cb = self.cc.QCheckBox(tag[2])
            self.tags_map[tags_cb] = tag
            if tag in self.context_filter.enabled_tags:
                tags_cb.setChecked(True)
            if index > 0 and index % height_split == 0:
                vbox_widget = self.cc.QWidget()
                vbox_widget.setLayout(current_col_vbox)
                self.tags_hbox.addWidget(vbox_widget)
                current_col_vbox = self.cc.QVBoxLayout()
            if index == (len(self.context_filter.tags) - 1):
                current_col_vbox.addWidget(tags_cb)
                current_col_vbox.addStretch(1)
                vbox_widget = self.cc.QWidget()
                vbox_widget.setLayout(current_col_vbox)
                self.tags_hbox.addWidget(vbox_widget)
            else:
                current_col_vbox.addWidget(tags_cb)
        self.tags_hbox.addStretch(1)
        self.tags_box.setLayout(self.tags_hbox)

    def _createGroupsBox(self):
        self.groups_box = self.cc.QGroupBox("Display Groups")
        self.groups_vbox = self.cc.QVBoxLayout()
        self.groups_map = {}
        for group in self.context_filter.groups:
            groups_cb = self.cc.QCheckBox(group[2])
            self.groups_map[groups_cb] = group
            if group in self.context_filter.enabled_groups:
                groups_cb.setChecked(True)
            self.groups_vbox.addWidget(groups_cb)
        self.groups_vbox.addStretch(1)
        self.groups_box.setLayout(self.groups_vbox)

    def _createGroupsTagsWidget(self):
        self.groups_tags_widget = self.cc.QWidget()
        self.groups_tags_hbox = self.cc.QHBoxLayout()
        self.groups_tags_hbox.addWidget(self.tags_box)
        self.groups_tags_hbox.addWidget(self.groups_box)
        self.groups_tags_hbox.addStretch(1)
        self.groups_tags_widget.setLayout(self.groups_tags_hbox)

    def _createAdditionalsBox(self):
        self.additionals_box = self.cc.QGroupBox("Additional Information")
        self.additionals_vbox = self.cc.QVBoxLayout()
        self.additionals_map = {}
        for additional in self.context_filter.additionals:
            additional_cb = self.cc.QCheckBox(additional[2])
            self.additionals_map[additional_cb] = additional
            if additional in self.context_filter.enabled_additionals:
                additional_cb.setChecked(True)
            self.additionals_vbox.addWidget(additional_cb)
        self.additionals_vbox.addStretch(1)
        self.additionals_box.setLayout(self.additionals_vbox)

    def _createDecisionWidget(self):
        self.decision_widget = self.cc.QWidget()
        self.decision_layout = self.cc.QVBoxLayout()
        self.decision_layout.addWidget(self.grouping_mode_box)
        self.decision_layout.addWidget(self.groups_tags_widget)
        self.decision_layout.addWidget(self.additionals_box)
        self.decision_widget.setLayout(self.decision_layout)

    def _createButtons(self):
        self.button_layout = self.cc.QHBoxLayout()
        self.ok_button = self.cc.QPushButton(self.tr("OK"))
        self.cancel_button = self.cc.QPushButton(self.tr("Cancel"))
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        self.button_layout.addStretch(1)
        self.button_layout.addWidget(self.ok_button)
        self.button_layout.addWidget(self.cancel_button)

    def accept(self):
        # display mode
        self.context_filter.display_tags = self.grouping_mode_tags.isChecked()
        self.context_filter.display_groups = self.grouping_mode_grouped.isChecked()
        self.context_filter.display_all = self.grouping_mode_all.isChecked()
        # tags
        self.context_filter.enabled_tags = []
        for tag_cb in self.tags_map:
            if tag_cb.isChecked():
                self.context_filter.enabled_tags.append(self.tags_map[tag_cb])
        self.context_filter.enabled_tags.sort()
        # groups
        self.context_filter.enabled_groups = []
        for group_cb in self.groups_map:
            if group_cb.isChecked():
                self.context_filter.enabled_groups.append(self.groups_map[group_cb])
        self.context_filter.enabled_groups.sort()
        # additionals
        self.context_filter.enabled_additionals = []
        for additional_cb in self.additionals_map:
            if additional_cb.isChecked():
                self.context_filter.enabled_additionals.append(self.additionals_map[additional_cb])
        self.context_filter.enabled_additionals.sort()

        self.done(1)

    def getAdjustedFunctionFilter(self):
        return self.context_filter

    def _updateGroupingModeDisplay(self):
        if self.grouping_mode_tags.isChecked():
            self.tags_box.setEnabled(True)
            self.groups_box.setEnabled(False)
        elif self.grouping_mode_grouped.isChecked():
            self.tags_box.setEnabled(False)
            self.groups_box.setEnabled(True)
        else:
            self.tags_box.setEnabled(False)
            self.groups_box.setEnabled(False)

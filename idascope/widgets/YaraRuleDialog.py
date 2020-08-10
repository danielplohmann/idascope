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


class YaraRuleDialog(QDialog):
    """ oriented on: https://stackoverflow.com/a/11764475 """

    def __init__(self, parent, rule):
        self.cc = parent.cc
        self.cc.QDialog.__init__(self, parent)
        # references to Qt-specific modules
        # create GUI elements
        self.rule = rule
        self._createOkButton()
        # glue everything together
        # create scroll for rule text edit
        self.scroll = self.cc.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setVerticalScrollBarPolicy(self.cc.QtCore.Qt.ScrollBarAlwaysOn)
        sizePolicy = self.cc.QSizePolicy(self.cc.QSizePolicy.Expanding, self.cc.QSizePolicy.Preferred)
        self.setSizePolicy(sizePolicy)
        scrollContents = self.cc.QWidget()
        self.scroll.setWidget(scrollContents)
        # create growing textedit for rule display
        self.textLayout = self.cc.QVBoxLayout()
        self.rule_textedit = self.cc.GrowingTextEdit(self)
        self.setMinimumHeight(300)
        self.setMinimumWidth(550)
        self.rule_textedit.setReadOnly(True)
        self.textLayout.addWidget(self.rule_textedit)

        dialog_layout = self.cc.QVBoxLayout(scrollContents)

        dialog_layout.addLayout(self.textLayout)
        dialog_layout.addLayout(self.button_layout)
        self.setLayout(dialog_layout)
        if self.rule:
            self.setWindowTitle(self.tr("YARA Rule: %s (%s)" % (self.rule.rule_name, self.rule.filename)))
            self.rule_textedit.setText(str(rule))
        else:
            self.setWindowTitle(self.tr("No rule selected."))

    def _createOkButton(self):
        self.button_layout = self.cc.QHBoxLayout()
        self.ok_button = self.cc.QPushButton(self.tr("OK"))
        self.ok_button.clicked.connect(self.accept)
        self.button_layout.addStretch(1)
        self.button_layout.addWidget(self.ok_button)
        self.button_layout.addStretch(1)

    def accept(self):
        self.done(1)


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
QWidget = QtShim.get_QWidget()

import idascope.core.helpers.Misc as Misc


class WinApiWidget(QWidget):
    """
    A widget for allowing easy access to Windows API information. Front-end to the I{idascope.core.WinApiProvider}.
    """

    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QWidget.__init__(self)
        print "[|] loading WinApiWidget"
        self.parent = parent
        self.name = "WinAPI"
        self.icon = self.cc.QIcon(self.parent.config.icon_file_path + "winapi.png")
        self.search_icon = self.cc.QIcon(self.parent.config.icon_file_path + "search.png")
        self.back_icon = self.cc.QIcon(self.parent.config.icon_file_path + "back.png")
        self.forward_icon = self.cc.QIcon(self.parent.config.icon_file_path + "forward.png")
        self.online_icon = self.cc.QIcon(self.parent.config.icon_file_path + "online.png")
        self.ida_proxy = self.cc.ida_proxy
        self.winapi = self.parent.winapi_provider
        self.old_keyword_initial = ""
        self.winapi.registerDataReceiver(self.populateBrowserWindow)
        self._createGui()
        self._updateAvailability()
        self._registerHotkeys()

    def _updateAvailability(self):
        """
        Adjust the availability of this widget by checking if the keyword database has been loaded or
        online mode is enabled.
        """
        if not self.winapi.hasOfflineMsdnAvailable() and \
            not self.winapi.hasOnlineMsdnAvailable():
            self.browser_window.setHtml("<p><font color=\"#FF0000\">Offline MSDN database is not available. To use " \
                + "it, have a look at the installation instructions located in the manual: " \
                + "IDAscope/documentation/manual.html. Online mode is deactivated as well.</font></p>")
            self.search_button.setEnabled(False)
            self.api_chooser_lineedit.setEnabled(False)
        else:
            self.browser_window.setHtml("<p>Enter a search term in the above field to search offline/online MSDN.</p>")
            self.search_button.setEnabled(True)
            self.api_chooser_lineedit.setEnabled(True)

    def _registerHotkeys(self):
        """
        Register hotkeys with IDAscope in order to ease the use of this widget.
        """
        self.parent.registerHotkey(self.parent.config.winapi_shortcut, self._navigateToHighlightedIdentifier)

    def _createGui(self):
        """
        Create the GUI for this widget and all of its components.
        """
        self._createBackButton()
        self._createNextButton()
        self._createOnlineButton()
        self._createApiChooserLineedit()
        self._createSearchButton()
        self._createBrowserWindow()

        winapi_layout = self.cc.QVBoxLayout()
        selection_widget = self.cc.QWidget()
        selection_layout = self.cc.QHBoxLayout()
        selection_layout.addWidget(self.online_button)
        selection_layout.addWidget(self.back_button)
        selection_layout.addWidget(self.next_button)
        selection_layout.addWidget(self.api_chooser_lineedit)
        selection_layout.addWidget(self.search_button)
        selection_widget.setLayout(selection_layout)
        winapi_layout.addWidget(selection_widget)
        winapi_layout.addWidget(self.browser_window)
        self.setLayout(winapi_layout)

    def _createBackButton(self):
        """
        Create a back button to allow easier browsing
        """
        self.back_button = self.cc.QPushButton(self.back_icon, "", self)
        self.back_button.setToolTip("Go back to previously accessed content.")
        self.back_button.resize(self.back_button.sizeHint())
        self.back_button.setEnabled(False)
        self.back_button.clicked.connect(self._onBackButtonClicked)

    def _createNextButton(self):
        """
        Create a next button to allow easier browsing
        """
        self.next_button = self.cc.QPushButton(self.forward_icon, "", self)
        self.next_button.setToolTip("Go forward to previously accessed content.")
        self.next_button.resize(self.next_button.sizeHint())
        self.next_button.setEnabled(False)
        self.next_button.clicked.connect(self._onNextButtonClicked)

    def _createOnlineButton(self):
        """
        Create a next button to allow easier browsing
        """
        self.online_button = self.cc.QPushButton(self.online_icon, "", self)
        self.online_button.setCheckable(True)
        if self.winapi.hasOnlineMsdnAvailable():
            self.online_button.setChecked(self.cc.QtCore.Qt.Checked)
        self.online_button.setToolTip("Enable/disable MSDN online lookup.")
        self.online_button.resize(self.online_button.sizeHint())
        self.online_button.clicked.connect(self._onOnlineButtonClicked)

    def _createApiChooserLineedit(self):
        """
        Create the I{QLineEdit }used for selecting API names. This includes a QCompleter to make suggestions based on
        the keyword database.
        """
        self.api_chooser_lineedit = self.cc.QLineEdit()
        self.api_chooser_lineedit.returnPressed.connect(self.populateBrowserWindow)
        self.api_chooser_lineedit.textChanged.connect(self._updateCompleterModel)

        completer = self.cc.QCompleter()
        completer.setCaseSensitivity(self.cc.QtCore.Qt.CaseInsensitive)
        completer.setModelSorting(self.cc.QCompleter.CaseSensitivelySortedModel)
        self.completer_model = self.cc.QStringListModel([])
        completer.setModel(self.completer_model)
        self.api_chooser_lineedit.setCompleter(completer)

    def _createSearchButton(self):
        """
        Create a search button besides the QLineEdit.
        """
        self.search_button =  self.cc.QPushButton(self.search_icon, "", self)
        self.search_button.setToolTip("Search for the chosen API name, structure or whatever WinAPI documentation " \
            + "might have for you.")
        self.search_button.resize(self.search_button.sizeHint())
        self.search_button.clicked.connect(self._onSearchButtonClicked)

    def _createBrowserWindow(self):
        """
        Create the browser window with a I{QTextBrowser}. This display component is chosen over I{QWebView} because
        WebKit is not included in the standard PySide installation as distributed with IDA Pro.
        """
        self.browser_window =  self.cc.QTextBrowser()
        self.browser_window.anchorClicked.connect(self._browserAnchorClicked)

    def _updateCompleterModel(self):
        """
        Update the completer model used to make suggestions. The model is only updated if anything is entered into the
        search line and the initial character differs from the previous initial character.
        """
        keyword_data = []
        api_chooser_text = self.api_chooser_lineedit.text()
        if len(api_chooser_text) > 0:
            keyword_initial = api_chooser_text[0].lower()
            if keyword_initial != self.old_keyword_initial:
                self.old_keyword_initial = keyword_initial
                keyword_data = self.winapi.getKeywordsForInitial(keyword_initial)
                self.completer_model.setStringList(keyword_data)

    def populateBrowserWindow(self, content=""):
        """
        Populate the browser window based upon the entered term in the search line.
        @param content: the content to render in the browser
        @type content: str
        """
        if content == "":
            api_chooser_text = self.api_chooser_lineedit.text()
            if len(api_chooser_text) > 0:
                content = self.winapi.getKeywordContent(api_chooser_text)
        self.browser_window.setHtml(content)
        self._updateHistoryButtonState()

    def _onSearchButtonClicked(self):
        """
        Action that is performed when the search button is clicked. This will populate the browser window.
        """
        self.populateBrowserWindow()

    def _onBackButtonClicked(self):
        """
        Action that is performed when the search button is clicked. This will populate the browser window.
        """
        document_content, anchor = self.winapi.getPreviousDocumentContent()
        if document_content != "":
            self.browser_window.setHtml(document_content)
        self.browser_window.scrollToAnchor(anchor)
        self._updateHistoryButtonState()

    def _onNextButtonClicked(self):
        """
        Action that is performed when the search button is clicked. This will populate the browser window.
        """
        document_content, anchor = self.winapi.getNextDocumentContent()
        if document_content != "":
            self.browser_window.setHtml(document_content)
        self.browser_window.scrollToAnchor(anchor)
        self._updateHistoryButtonState()

    def _onOnlineButtonClicked(self):
        """
        Action that is performed when the search button is clicked. This will populate the browser window.
        """
        self.winapi.setOnlineMsdnEnabled(not self.winapi.hasOnlineMsdnAvailable())
        self._updateAvailability()

    def _browserAnchorClicked(self, url):
        """
        Callback for the case an anchor (or any link) within the browser window is clicked. This will fetch
        document content and anchor based on the URL of the link and update the browser window.
        @param url: a URL as triggered by the callback
        @type url: QUrl
        """
        document_content, anchor = self.winapi.getLinkedDocumentContent(url)
        if document_content != "":
            self.browser_window.setHtml(document_content)
        self.browser_window.scrollToAnchor(anchor)
        self._updateHistoryButtonState()

    def navigate(self, api_name):
        """
        A function exposed in order to allow the widget to be navigated to an arbitrary API name.
        @param api_name: the API name to navigate the widget to.
        @type api_name: str
        """
        self.api_chooser_lineedit.setText(api_name)
        self.populateBrowserWindow()

    def _navigateToHighlightedIdentifier(self):
        """
        A function exposed to allow navigating the widget to the currently highlighted identifier from the IDA view.
        """
        if self.winapi.hasOfflineMsdnAvailable():
            highlighted_identifier = self.cc.Misc.cleanCountingSuffix(self.ida_proxy.get_highlighted_identifier())
            highlighted_identifier = self.parent.semantic_identifier.lookupDisplayApiName(highlighted_identifier)
            self.navigate(highlighted_identifier)
            self.parent.setTabFocus(self.name)

    def _updateHistoryButtonState(self):
        """
        Update the button state (enabled/disabled) according to availability of history information from the
        WinApiProvider
        """
        self.back_button.setEnabled(self.winapi.hasBackwardHistory())
        self.next_button.setEnabled(self.winapi.hasForwardHistory())


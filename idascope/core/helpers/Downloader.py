#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  a QThread for downloading web content.
#
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

# TODO: Make this finally multi-threaded.
import httplib

import idascope.core.helpers.QtShim as QtShim
QtGui = QtShim.get_QtGui()
QtCore = QtShim.get_QtCore()
Signal = QtShim.get_Signal()

from ThreadedDownloader import ThreadedDownloader


class TempQThread(QtCore.QThread):

    def __init__(self, parent=None):
        QtCore.QThread.__init__(self, parent)

    def run(self):
        self.exec_()

    def __str__(self):
        return "0x%08X" % id(self)


class Downloader(QtCore.QObject):
    """
    A class to download web content. Works both blocking and non-blocking (threaded with callback).
    """

    downloadFinished = Signal()

    def __init__(self):
        super(Downloader, self).__init__()
        self.httplib = httplib
        self.TempQThread = TempQThread
        self.ThreadedDownloader = ThreadedDownloader
        self._data = None
        self.download_thread = None
        self.download_url = ""

    def downloadThreaded(self, url):
        """
        Start a new download thread. Will notify via signal "downloadFinished" when done.
        @param url: The URL to download from.
        @type url: str
        """
        self.download_thread = self.TempQThread()
        self.download_worker = self.ThreadedDownloader(url)
        self.download_worker.moveToThread(self.download_thread)
        self.download_worker.threadFinished.connect(self._onThreadFinished)
        self.download_thread.started.connect(self.download_worker.setup)
        # starts thread event loop and triggers my_thread.started (and in turn, setup)
        self.download_thread.start()
        # in the end
        # quit thread's event loop (thread will end)
        if self.download_thread.isRunning():
            self.download_thread.quit()
            # self.download_thread.wait(5000)
        # clean up thread object
        self.download_worker.shutdown()

    def setDownloadUrl(self, url):
        # print "Downloader.setDownloadUrl(): called, setting download_url to: %s" % self.download_url
        self.download_url = url

    def downloadStoredUrl(self):
        # print "Downloader.downloadStoredUrl(): called, download_url is: %s" % self.download_url
        self.downloadSignalled(self.download_url)

    def download(self, url):
        """
        Start a blocking download. Will return the downloaded content when done.
        @param url: The URL to download from.
        @type url: str
        @return: (str) the downloaded content.
        """
        # print "Downloader.download(): type of received parameter: ", type(url)
        host = url[8:url.find("/", 8)]
        path = url[url.find("/", 8):]
        try:
            conn = self.httplib.HTTPSConnection(host)
            conn.request("GET", path)
            response = conn.getresponse()
            if response.status == 200:
                print "[+] Downloaded from: %s" % (url)
                self._data = response.read()
            else:
                print "[-] Download failed: %s (%s %s)" % (url, response.status, response.reason)
                self._data = "Download failed (%s %s)!" % (response.status, response.reason)
            conn.close()
        except Exception as exc:
            print ("[!] Downloader.download: Exception while downloading: %s" % exc)
            self._data = None
        return self._data

    def downloadSignalled(self, url):
        # print "Downloader.downloadSignalled(): called"
        self.download(url)
        self.downloadFinished.emit()

    def getData(self):
        """
        Returns the previously downloaded data.
        """
        return self._data

    def _onThreadFinished(self):
        if self.download_thread:
            self._data = self.download_thread.getData()
            self.download_thread = None
        self.downloadFinished.emit()

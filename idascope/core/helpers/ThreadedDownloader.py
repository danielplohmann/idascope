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
#######################################################################

import httplib

import idascope.core.helpers.QtShim as QtShim
QtGui = QtShim.get_QtGui()
QtCore = QtShim.get_QtCore()
Signal = QtShim.get_Signal()


class ThreadedDownloader(QtCore.QObject):

    threadFinished = Signal()

    def __init__(self, url):
        super(ThreadedDownloader, self).__init__()
        self.httplib = httplib
        self.QtCore = QtCore
        self.url = url
        self._data = None

    def setup(self):
        # loop setup (0 timer): optional
        self.loop_timer = self.QtCore.QTimer()
        self.loop_timer.timeout.connect(self.loop)
        self.loop_timer.start(0)
        self.run()
        self.threadFinished.emit()

    def shutdown(self):
        # do clean-up
        pass

    def loop(self):
        pass

    def run(self):
        host = self.url[7:self.url.find("/", 7)]
        path = self.url[self.url.find("/", 7):]
        try:
            conn = self.httplib.HTTPConnection(host)
            conn.request("GET", path)
            response = conn.getresponse()
            print response.status, response.reason
            self._data = response.read()
            conn.close()
        except Exception as exc:
            print ("[!] ThreadedDownloader.run: Exception while downloading: %s" % exc)
            self._data = None
        finally:
            self.threadFinished.emit()

    def getData(self):
        return self._data

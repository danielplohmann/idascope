import idascope.core.helpers.QtShim as QtShim
QTextEdit = QtShim.get_QTextEdit()


class GrowingTextEdit(QTextEdit):
    """ source: https://stackoverflow.com/a/11764475 """

    def __init__(self, parent, *args, **kwargs):
        self.cc = parent.cc
        self.cc.QTextEdit.__init__(self)
        self.document().contentsChanged.connect(self.sizeChange)

        self.heightMin = 0
        self.heightMax = 1400

    def getHeight(self):
        return self.document().size().height()

    def sizeChange(self):
        docHeight = self.getHeight()
        if self.heightMin <= docHeight <= self.heightMax:
            self.setMinimumHeight(docHeight)

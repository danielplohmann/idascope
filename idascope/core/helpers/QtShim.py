
# inspired by this gist of Willi Ballenthin
# https://gist.github.com/williballenthin/277eedca569043ef0984

import idaapi


def get_QtCore():
    if idaapi.IDA_SDK_VERSION <= 680:
        # IDA 6.8 and below
        import PySide.QtCore as QtCore
        return QtCore
    else:
        # IDA 6.9
        import PyQt5.QtCore as QtCore
        return QtCore


def get_QtGui():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui
    else:
        import PyQt5.QtGui as QtGui
        return QtGui


def get_QtWidgets():
    if idaapi.IDA_SDK_VERSION <= 680:
        return None
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets


def get_QTreeWidget():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidget
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidget


def get_QTreeWidgetItem():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidgetItem
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidgetItem


def get_QTableWidgetItem():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidgetItem
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem


def get_QIcon():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QIcon
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QIcon


def get_QWidget():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QWidget
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QWidget


def get_QVBoxLayout():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QVBoxLayout
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QVBoxLayout


def get_QHBoxLayout():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QHBoxLayout
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QHBoxLayout


def get_QSplitter():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSplitter
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSplitter


def get_QStyleFactory():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyleFactory
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleFactory 


def get_QStyleOptionSlider():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyleOptionSlider
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleOptionSlider 


def get_QApplication():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QApplication
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QApplication 


def get_QPainter():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QPainter
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QPainter 


def get_DescendingOrder():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.Qt.SortOrder.DescendingOrder
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.Qt.DescendingOrder


def get_QTabWidget():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTabWidget
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTabWidget 


def get_QStyle():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyle
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyle 


def get_QLabel():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QLabel
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLabel


def get_QTableWidget():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidget
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidget


def get_QTableWidgetItem():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidgetItem
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem


def get_QPushButton():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QPushButton
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QPushButton


def get_QAbstractItemView():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QAbstractItemView
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAbstractItemView


def get_QScrollArea():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QScrollArea
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QScrollArea


def get_QSizePolicy():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSizePolicy
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSizePolicy


def get_QLineEdit():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QLineEdit
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLineEdit


def get_QCompleter():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QCompleter
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCompleter


def get_QTextBrowser():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTextBrowser
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextBrowser


def get_QSlider():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSlider
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSlider


def get_QMainWindow():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QMainWindow
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QMainWindow


def get_QTextEdit():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTextEdit
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextEdit


def get_QDialog():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QDialog
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QDialog


def get_QGroupBox():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QGroupBox
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QGroupBox


def get_QRadioButton():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QRadioButton
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QRadioButton


def get_QComboBox():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QComboBox
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QComboBox


def get_QCheckBox():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QCheckBox
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCheckBox


def get_QAction():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QAction
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAction


def get_QBrush():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QBrush
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QBrush


def get_QColor():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QColor
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QColor


def get_QStringListModel():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStringListModel
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QStringListModel


def get_Signal():
    if idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.Signal
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.pyqtSignal

simpliFiRE.IDAscope - An IDA Pro extension for easier (malware) reverse engineering
===================================================================================

Description
-----------

IDAscope is an IDA Pro extension with the goal to ease the task of (malware) reverse engineering with a current focus on x86 Windows. It consists of multiple tabs, containing functionality to achieve different goals such as fast identification of semantically interesting locations in the analysis target, seamless access to MSDN documentation of Windows API, and finding of potential crypto/compression algorithms.

Instructions
------------

Go to https://bitbucket.org/daniel_plohmann/simplifire.idascope/ and download a release package or check out the repository for the latest version of IDAscope. 

Basic installation is easy: unzipping the package in a location where it can be reached from IDA Pro is enough. To use the extension, simply run IDAscope.py from the root directory via IDA Pro's "File / Script File". 

To make the MSDN database to the WinAPI browser available, follow the steps described in IDAscope/documentation/manual.html.

Final Words
-----------

IDAscope has functionality (annotation, coloring, code conversion, ...) that can alter your IDB. While it should normally not happen, we cannot guarantee that it will not break the IDB of your analysis target. Therefore, we recommend making backups before using it. By using this tool, we assume that you know what you are doing and you accept that you are using it on your own risk. As stated in the license, we will not take liability for any damage caused by this tool.

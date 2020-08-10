# IDAscope - An IDA Pro extension for easier (malware) reverse engineering

IDAscope is an IDA Pro extension with the goal to ease the task of (malware) reverse engineering with a current focus on x86 Windows.  
It consists of multiple tabs, containing functionality to achieve different goals such as fast identification of semantically interesting locations in the analysis target, seamless access to MSDN documentation of Windows API, and finding of potential crypto/compression algorithms.

## Instructions

Go to https://github.com/danielplohmann/idascope and download a release package or check out the repository for the latest version of IDAscope. 

Basic installation is easy: unzipping the package in a location where it can be reached from IDA Pro should suffice.  
To use the extension, simply run IDAscope.py from the root directory via IDA Pro's "File / Script File". 

To make the MSDN database to the WinAPI browser available, follow the steps described in IDAscope/documentation/manual.html.

## Caution!

IDAscope has functionality (annotation, coloring, code conversion, ...) that can alter your IDB. While it should normally not happen, we cannot guarantee that it will not break the IDB of your analysis target. Therefore, we recommend making backups before using it.  
By using this tool, we assume that you know what you are doing and you accept that you are using it on your own risk. As stated in the license, we will not take liability for any damage caused by this tool.

## Credits

The idea for the plugin was born at [RECON 2012](http://recon.cx) out of some prototype scripts created by Daniel and Alex.  
Some more history is preserved in the blogs of [Daniel](https://danielplohmann.github.io/) and [Alex](http://hooked-on-mnemonics.blogspot.com/).

Authors and contributors of IDAscope are [Daniel Plohmann](https://twitter.com/push_pnx), [Alexander Hanel](https://twitter.com/nullandnull), 
[Luca Corbatto](https://github.com/targodan), [Jean-Michel Picod](https://twitter.com/jmichel_p), Branko Spasojevic, [Sascha Rommelfangen](https://twitter.com/rommelfs)

## Version History
 * 2020-08-10 -- v1.3: Move to Github, Adaptions for IDA 7.0+ and Python3 - Eternal THX to Luca Corbatto for making the modernization happen!
 * 2018-08-13 -- v1.2.1: Minor fixes on YaraScanner and CryptoIdentifier - thanks to Jean-Michel Picod
 * 2016-01-08 -- v1.2.1: Support up to IDA 6.9 with PyQt5.
 * 2014-02-07 -- v1.2: Added [SemanticExplorer](https://www.botconf.eu/wp-content/uploads/2014/12/2014-1.3-Semantic-Exploration-of-Binaries.pdf) to IDAscope.
 * 2014-02-07 -- v1.1: Added YARA Scanning to IDAscope.
 * 2012-12-13 -- IDAscope wins the [2012 IDA Plugin contest](https://www.hex-rays.com/contests_details/contest2012/)!
 * 2012-09-18 -- v1.0a: The original release!
# DroidGraph [![Build Status](https://travis-ci.org/DarioI/droidgraph.svg?branch=master)](https://travis-ci.org/DarioI/droidgraph)

DroidGraph disassembles bytecode in the Android .apk file and will generate 
various graphs to get insight in the code. All the graphs are exported as 
.dot files which you can view in .dot viewers like for example [GraphViz]
(http://www.graphviz.org)

For disassembling DEX bytecode, DroidGraph uses the [smali/baksmali]
(https://github.com/JesusFreke/smali) disassembler developed by Ben Gruver.

## Requirements

Python 2.7 and pip.

## Installing DroidGraph

```shell
$ git clone https://github.com/DarioI/droidgraph

$ cd droidgraph

$ pip install -r requirements.txt
```
## Using DroidGraph

```shell
$ python droidgraph.py -h
usage: droidgraph.py [-h] -a APK [-d DIRECTORY] [-i INCLUDE] [-x EXCLUDE]

Create different graphs from Android DEX bytecode to get insight in the code
structure.

optional arguments:
  -h, --help            show this help message and exit
  -a APK, --apk APK     APK file to analyze
  -d DIRECTORY, --directory DIRECTORY
                        Directory to which the graphs should be printed
  -i INCLUDE, --include INCLUDE
                        Specify a list of regexes that define the classes to
                        be included in the scope (OPTIONAL)
  -x EXCLUDE, --exclude EXCLUDE
                        Specify a list of regexes that define the classes to
                        be excluded in the scope (OPTIONAL)
```

## Including and excluding

DroidGraph can be instructed to include or exclude certain classes. The 
includes.txt file shows a simple example on how to only include the Android 
support v4 library. If you do not specify any include or exclude list, the 
whole codebase of the APK is exported and shown in the graphs.

## RoadMap

* Dependency graph
* Call graph

## Smali/Baksmali License

The majority of smali/baksmali is written and copyrighted by me (Ben Gruver)
and released under the following license:

*******************************************************************************
Copyright (c) 2010 Ben Gruver (JesusFreke)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************
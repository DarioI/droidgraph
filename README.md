# DroidGraph

DroidGraph disassembles bytecode in Android .apk file and will generate 
various graphs to get insight in the code. All the graphs are exported as 
.dot files which you can view in .dot viewers like for example [GraphViz]
(http://www.graphviz.org)

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
whole code based is exported and shown in the graphs.
## RoadMap

* Dependency graph
* Call graph
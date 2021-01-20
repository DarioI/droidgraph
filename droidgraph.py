# This file is part of DroidGraph.
#
# Copyright (C) 2021, Dario Incalza <dario.incalza at gmail.com>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse, os, shutil, re, hashlib
from subprocess import call
from networkx.drawing.nx_pydot import write_dot
import networkx as nx
from zipfile import ZipFile

__author__ = 'Dario Incalza <dario.incalza@gmail.com>'

BAKSMALI_PATH = os.getcwd() + "/bin/baksmali.jar"
APK_FILE = ""
CACHE_PATH = os.getcwd() + "/cache/"
DEX_DIR = CACHE_PATH + "dex/"
SMALI_DIR = CACHE_PATH + "smali/"
GRAPH_PATH = os.getcwd()
EXCLUDE_LIST = []
INCLUDE_LIST = []

'''
Check if there is a baksmali tool.
'''


def has_baksmali():
    return os.path.isfile(BAKSMALI_PATH)


'''
Determine if the given regex is valid.
'''


def isValidRegEx(regex):
    try:
        re.compile(regex)
        return True
    except re.error:
        return False


'''
Parse a given file of regular expressions and only add them if they are valid
regexes.
'''


def parse_configuration_list(file):
    result = []
    with open(file, 'r') as f:
        for line in f:
            if line.strip(' \t\n\r').startswith("#"):
                continue
            regex = line.strip(' \t\n\r')
            if not regex:
                continue
            if not isValidRegEx(regex):
                print("CONFIG ERR: Ignoring %s because it is not a valid regex." % regex)
            else:
                result.append(regex)
    return result


'''
Parse the arguments and assign global variables that we will be using throughout the tool.
'''


def parse_arguments():
    parser = argparse.ArgumentParser(description='Create different graphs '
                                                 'from Android DEX bytecode '
                                                 'to get insight in the code '
                                                 'structure.')
    parser.add_argument('-a', '--apk', type=str, help='APK file to analyze',
                        required=True)
    parser.add_argument('-d', '--directory', type=str, help="Directory to "
                                                            "which the graphs "
                                                            "should be "
                                                            "printed")
    parser.add_argument('-i', '--include', type=str, help='Specify a list of '
                                                          'regexes that '
                                                          'define the classes '
                                                          'to be '
                                                          'included in the '
                                                          'scope (OPTIONAL)')
    parser.add_argument('-x', '--exclude', type=str, help='Specify a list of '
                                                          'regexes that '
                                                          'define the classes '
                                                          'to be '
                                                          'excluded in the '
                                                          'scope (OPTIONAL)')
    args = parser.parse_args()

    global APK_FILE
    APK_FILE = args.apk

    global GRAPH_PATH
    if args.directory is not None:
        GRAPH_PATH = args.directory
    else:
        GRAPH_PATH = os.getcwd()

    global INCLUDE_LIST
    if args.include is not None:
        INCLUDE_LIST = parse_configuration_list(args.include)
        for regex in INCLUDE_LIST:
            print("[*] CONFIG: Including classes matching %s" % regex)

    global EXCLUDE_LIST
    if args.exclude is not None:
        EXCLUDE_LIST = parse_configuration_list(args.exclude)
        for regex in EXCLUDE_LIST:
            print("[*] CONFIG: Excluding classes matching %s" % regex)


'''
Sanity check to see if a valid APK file is specified.

TODO: implement more specific check to see if it is a valid APK file
'''


def check_apk_file():
    if APK_FILE == "" or not os.path.isfile(APK_FILE):
        print("[!!!] ERR: No APK file specified, exiting.")
        exit(3)


'''
Use baksmali to disassemble the .DEX files.
'''


def disassemble_dex_files():
    dex_files = get_dex_files(APK_FILE)

    if len(dex_files) > 1:
        print("[*] MultiDex APK detected with {} .DEX files".format(len(dex_files)))
    else:
        print("[*] Single .DEX file detected")
    for dexfn in dex_files:
        print("\t[|]Disassembling {}".format(dexfn))
        disassemble_dex_file(dexfilename=dexfn)


'''
Disassemble the Dex bytecode of a given APK source, a specified DEX File (e.g., classes.dex) to a given smali cache sink
'''


def disassemble_dex_file(dexfilename='classes.dex'):
    zf = ZipFile(APK_FILE, mode='r')
    with zf.open(dexfilename) as dexfile:
        df = dexfile.read()
        f = open(DEX_DIR + "{}".format(dexfilename), "wb")
        f.write(df)
        f.close()
        dexfile.close()

    call(["java", "-jar", BAKSMALI_PATH, "d", DEX_DIR + "{}".format(dexfilename), "-o", SMALI_DIR])


'''
Get a list of strings representing the .dex files available in the APK
'''


def get_dex_files(apkfile):
    zf = ZipFile(apkfile, mode='r')
    file_list = zf.namelist()
    idx = 2
    dexs = []
    if 'classes.dex' in file_list:
        dexs.append("classes.dex")
    else:
        print('[!!!] classes.dex not found, invalid APK')
        exit(-1)
    while True:
        if 'classes{}.dex'.format(idx) in file_list:
            dexs.append('classes{}.dex'.format(idx))
            idx = idx + 1
        else:
            break
    return dexs


'''
Clear the cache directory.
'''


def clear_cache():
    try:
        shutil.rmtree(CACHE_PATH)
        os.makedirs(CACHE_PATH)
        os.makedirs(SMALI_DIR)
        os.makedirs(DEX_DIR)
    except OSError:
        os.makedirs(CACHE_PATH)


'''
Extract class name from a smali source line. Every class name is represented
as a classdescriptor that starts zith 'L' and ends with ';'.
'''


def extract_class_name(class_line):
    for el in class_line.split(" "):
        if el.startswith("L") and el.endswith(";"):
            return el


'''
Check if the class_name matches a regex in the include list

Note that letter case is ignored
'''


def is_included(class_name):
    if len(INCLUDE_LIST) == 0: return True

    for regex in INCLUDE_LIST:
        if re.compile(regex, re.IGNORECASE).match(class_name):
            return True

    return False


'''
Check if the class_name matches a regex in the exclude list

Note that letter case is ignored
'''


def is_excluded(class_name):
    if len(EXCLUDE_LIST) == 0: return False

    for regex in EXCLUDE_LIST:
        if re.compile(regex, re.IGNORECASE).match(class_name):
            return True

    return False


'''
Create the actual hierarchy graph from disassembled DEX bytecode.
'''


def create_hierarchy_graph():
    print("[*] Generating hierarchy graph")
    hierarchy_graph = nx.DiGraph()
    for subdir, dirs, files in os.walk(SMALI_DIR):
        for file in files:
            full_path = os.path.join(subdir, file)
            with open(full_path, 'r') as f:
                class_name = ""
                super_class = ""
                interfaces = []
                continue_loop = True
                for line in f:
                    if line.startswith(".class"):
                        class_line = line.strip(
                            "\n")  # extract the class line; always first line
                        class_name = extract_class_name(
                            class_line)  # extract the class descriptor
                        if not is_included(class_name) or is_excluded(
                                class_name):
                            continue_loop = False
                            break

                    if line.startswith(".super"):
                        super_class = extract_class_name(line.strip("\n"))

                    if line.startswith(".implements"):
                        interfaces.append(extract_class_name(line.strip("\n")))

                if not continue_loop:
                    continue

                if class_name == "":
                    print("[!!!] ERR: Could not parse class name from " + full_path)
                elif super_class == "":
                    print("[!!!] ERR: Could not parse super class name from " + full_path)
                else:
                    if not super_class == "Ljava/lang/Object;":
                        hierarchy_graph.add_edge(class_name, super_class,
                                                 label="C", color="blue")
                    if len(interfaces) > 0:
                        for interface in interfaces:
                            hierarchy_graph.add_edge(class_name, interface,
                                                     label="I", color="red")

    write_dot(hierarchy_graph, GRAPH_PATH + "/hierarchy.dot")
    print("[*] Hierarchy graph is located at {}".format(GRAPH_PATH + "/hierarchy.dot"))


'''
Get the SHA-256 hash of a given file
'''


def _get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def main():
    parse_arguments()
    check_apk_file()
    clear_cache()
    print("[*] DroidGraph - by Dario Incalza <dario.incalza@gmail.com>")
    print("[*] Using APK {} with hash {}".format(APK_FILE, _get_file_hash(APK_FILE)))
    disassemble_dex_files()
    create_hierarchy_graph()


if __name__ == "__main__":

    if not has_baksmali():
        print("[!!!] No baksmali.jar found in " + BAKSMALI_PATH)
        exit(2)

    main()

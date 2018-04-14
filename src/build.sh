#!/bin/bash

# Build script for building objconv on Linux, BSD and Mac OS X platforms.

# Instructions:

# You may need to change the path to bash above as required by your system

# Make sure the current directory contains all the .cpp files for objconv,
# and only one copy of each, and no other .cpp files

# Then run ./build.sh
# The compilation may take half a minute.

# Alternatively, run the following line:

g++ -o objconv -O2 *.cpp

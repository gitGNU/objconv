# the "invention" Makefile for `objconv' compilation with gcc

SRCS = src/*.cpp
OBJS = $(shell ls ${SRCS} | sed -e 's/\.cpp/.o/')

DEBUG =
WARNS = -Wall -Wextra
# compiler
CXX = g++
# compiler flags
CXXFLAGS = -O2 $(DEBUG) $(WARNS)
# linker flags
LFLAGS =

.PHONY: all clean

TARGET = objconv

all: $(OBJS)
	$(CXX) $(LFLAGS) -o $(TARGET) $^

clean:
	rm -f $(OBJS) $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

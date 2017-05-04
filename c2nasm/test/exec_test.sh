#!/bin/sh


test_clean(){
  rm -f hello.c.nasm
  rm -f hello.c.nasm.o  
  rm -f hello.c.o  
  rm -f hello.c.run
}

assert_exists(){
  [ -f "$1" ] || {
    echo "Test Failed: File $1 should exist"
    exit
  }
}
assert_return(){
  "$1"
  ret="$?"
  [ "$ret" == "$2" ] || {
    echo "Test Failed: Return of $1 should be $2, instead I got $ret "
    exit
  }
}
test_clean

../c2nasm.sh hello.c
assert_exists hello.c.nasm
assert_exists hello.c.nasm.o  
assert_exists hello.c.o  
assert_exists hello.c.run
assert_return ./hello.c.run 6

echo "=================="
echo All tests passed
echo "=================="


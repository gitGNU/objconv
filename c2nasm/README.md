
# C2NASM

Uses gcc and objconv to convert a C program to nasm.

To use it, give execution permission to c2nasm.sh and then:

```
./c2nasm.sh <sourcefile.c>
```

The result will be a .nasm file with the nasm, and a .run file which is the executable.

How to contribute: Send PR

Based on the question:
http://stackoverflow.com/questions/20737947/how-to-generate-a-nasm-compilable-assembly-code-from-c-source-code-on-linux/

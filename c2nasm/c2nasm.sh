#!/bin/sh
set -e
help(){
  echo "$1: Uses gcc and objconv to convert a C program to nasm"
  echo "usage: $1 <sourcefile.c>"
  exit 0
}
[ -z "$1" ] || [ "$1" == "-h" ] && help "$(dirname "$0")"

C_FILE="$1"
O_FILE="$C_FILE.o"
NASM_FILE="$C_FILE.nasm"
NASM_O_FILE="$NASM_FILE.o"
EXEC_FILE="$C_FILE.run"
gcc -m32 -c -o "$O_FILE" "$C_FILE"
objconv -fnasm "$O_FILE" "$NASM_FILE"
sed -i 's|st(0)|st0  |g' "$NASM_FILE"
sed -i 's|noexecute|         |g' "$NASM_FILE"
sed -i 's|execute|       |g' "$NASM_FILE"
sed -i 's|: function||g' "$NASM_FILE"
sed -i 's|?_|L_|g' "$NASM_FILE"
sed -i -n '/SECTION .eh_frame/q;p' "$NASM_FILE"
sed -i 's|;.*||g' "$NASM_FILE"
sed -i 's/^M//g' "$NASM_FILE"
sed -i 's|\s\+$||g' "$NASM_FILE"
sed -i 's|align=1||g' "$NASM_FILE"
echo 'Nasm file generated in '"$NASM_FILE"
nasm -f elf32 -o "$NASM_O_FILE" "$NASM_FILE"
gcc -m32 -lGL -lm -o "$EXEC_FILE"  "$NASM_O_FILE"
echo 'Successfully compiled '"$NASM_FILE" to "$EXEC_FILE"


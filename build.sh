#!/bin/bash

set -e

SRC="file_transfer.c"
OUT="file_transfer"

echo "Compiling $SRC -> $OUT ..."
gcc "$SRC" -o "$OUT" -lssl -lcrypto

echo "Build complete: ./$OUT"

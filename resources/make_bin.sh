#!/bin/zsh

INPUT_FILE="$1"
OUTPUT_FILE="$2"

OFFSET=`otool -l $INPUT_FILE | grep fileoff | sed 's/  fileoff //g' | tr -d '\n'`
dd if=$INPUT_FILE of=$OUTPUT_FILE ibs=$OFFSET skip=1

#!/bin/zsh

INPUT_FILE="$1"
OUTPUT_FILE="$2"

base64 -i $INPUT_FILE | tr -d '\n' > $OUTPUT_FILE

#!/bin/sh
# The test plaintext of a given size: "sootmark\n" repeated, cut to size.
# tests/interop.rs builds the same bytes.
yes sootmark 2>/dev/null | head -c "$1"

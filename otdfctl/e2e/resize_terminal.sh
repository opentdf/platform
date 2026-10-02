#!/bin/bash

####
# Make sure we have a terminal size large enough to test table output
####

## Accepts two arguments: rows and columns (both integers)

# Default terminal size
DEFAULT_ROWS=40
DEFAULT_COLUMNS=200

# Set rows and columns to the defaults or use the provided arguments
ROWS=${1:-$DEFAULT_ROWS}
COLUMNS=${2:-$DEFAULT_COLUMNS}

set_terminal_size_linux() {
    if command -v resize &> /dev/null; then
        resize -s "$ROWS" "$COLUMNS"
    else
        export COLUMNS="$COLUMNS"
        export LINES="$ROWS"
    fi
}

set_terminal_size_mac() {
    printf '\e[8;%d;%dt' "$ROWS" "$COLUMNS"
}

set_terminal_size_windows() {
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        printf '\e[8;%d;%dt' "$ROWS" "$COLUMNS"
    else
        cmd.exe /c "mode con: cols=$COLUMNS lines=$ROWS"
    fi
}

# Detect the OS and set the terminal size appropriately
case "$OSTYPE" in
    linux*)
        set_terminal_size_linux
        ;;
    darwin*)
        set_terminal_size_mac
        ;;
    msys* | cygwin* | win*)
        set_terminal_size_windows
        ;;
    *)
        echo "Unsupported OS: $OSTYPE"
        ;;
esac
#!/bin/bash

# Check if the required arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <outputDir> <checksumFile>"
    exit 1
fi

echo "Verifying checksums..."
# Location of the checksum file
checksumFile=$1/$2
outputDir=$1

echo "Looking for checksum file: $checksumFile"
test -f "$checksumFile" || { echo "ERROR: Checksum file not found!"; exit 1; }

# Iterate over each line in the checksum file
while read -r line; do
  # Extract the expected checksum and filename from each line
  read -ra ADDR <<< "$line" # Read the line into an array
  expectedChecksum="${ADDR[0]}"
  fileName="${ADDR[2]}"

  # Calculate the actual checksum of the file
  actualChecksum=$(shasum -a 256 "$outputDir/$fileName" | awk '{print $1}')

  # Compare the expected checksum with the actual checksum
  if [ "$expectedChecksum" == "$actualChecksum" ]; then
    echo "SUCCESS: Checksum for $fileName is valid."
  else
    echo "ERROR: Checksum for $fileName does not match."
  fi
done < "$checksumFile"
#!/bin/bash

# Build pom.xml files to be used when developing in Eclipse
# Note: No need to run this script unless changes to the original pom.xml files are done

# Usage: ./X.sh [optional/path]
ROOT_DIR="${1:-.}"

# Ensure xmlstarlet is installed
if ! command -v xmlstarlet &> /dev/null; then
    echo "xmlstarlet is not installed. Install it with: sudo apt install xmlstarlet"
    exit 1
fi

echo "Searching for pom.xml files under $ROOT_DIR..."

find "$ROOT_DIR" -type f -name "pom.xml" | while read -r pom; do
    echo "Processing: $pom"

    # Define output file name
    pom_dev="${pom%/*}/pom.dev"

    # Create cleaned version as pom.dev
    xmlstarlet ed \
        -N x="http://maven.apache.org/POM/4.0.0" \
        -d "//x:dependency[x:groupId='org.eclipse.californium']" \
        "$pom" > "$pom_dev"

    echo "Created cleaned version: $pom_dev"
done

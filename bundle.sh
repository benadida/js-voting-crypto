#!/bin/bash
##

echo ''
echo '****Bundling crypto for voting****'
echo ''

export PATH=$PATH:node_modules/.bin
BROWSERIFY=`which browserify 2> /dev/null`

if [ ! -x "$BROWSERIFY" ] ; then
    echo "can't find browserify.  try: npm install"
    exit 1
fi

INPUT="./bundle.js"
TMP="./tempbundle.js"
OUTPUT="./voting-crypto-bundle.js"
OUTPUT_MIN="./voting-crypto-bundle-min.js"

# remove the existing file if it exists
if [ -f "$OUTPUT" ]; then
    rm "$OUTPUT"
fi

browserify "$INPUT" --ignore crypto --ignore bigint -o "$TMP"
cat bundle-prelim.js > "$OUTPUT"
cat "$TMP" >> "$OUTPUT"
rm "$TMP"

# uglify
uglifyjs "$OUTPUT" > "$OUTPUT_MIN"
#!/bin/bash

# Download redbean if it doesn't exist
if [ ! -f redbean-3.0.0.com ]; then
    curl -o redbean-3.0.0.com https://redbean.dev/redbean-3.0.0.com
fi

# Copy to wallabean.com to start from scratch
cp redbean-3.0.0.com wallabean.com

# Put wallabean.lua into redbean
zip wallabean.com wallabean.lua

# Put .init.lua into redbean
zip wallabean.com .init.lua

# Put small logo into redbean
zip wallabean.com logo-small.png

# chmod
chmod +x wallabean.com

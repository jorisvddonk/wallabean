#!/bin/bash

# Build the project
./build.sh

# Kill all other wallabeans
pkill -f wallabean

# Kill any process listening on port 8080
kill -9 $(lsof -t -i :8080 -s TCP:LISTEN) 2>/dev/null || true

# Wait for port to be free
sleep 1

# Run wallabean
./wallabean.com

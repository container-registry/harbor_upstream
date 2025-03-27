#!/bin/sh

# Execute the core command directly
$1 &

# Get process ID of previously ran command
pid=$!

# Execute the command (passed as $1 arg)
echo "Executing: $1, with pid: $pid, with debug enabled"

# Start the dlv process in the background
# /root/go/bin/dlv exec --headless --listen localhost:$2 $1
# dlv --headless=true --listen=localhost:4001 --accept-multiclient --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc --log=true --continue --api-version=2 exec /core
dlv --headless=true --listen=0.0.0.0:4001 --accept-multiclient --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc --log=true --api-version=2 attach $pid

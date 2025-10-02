#!/bin/sh

# Execute the command (passed as $1 arg)
# echo "Executing:dlv --headless=true --allow-non-terminal-interactive=true --disable-aslr=true --listen=0.0.0.0:4001 --accept-multiclient=true --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc --log=true --continue --api-version=2 exec $1"
echo "Executing: dlv dap --listen=:4001 --api-version=2 exec $1"

# Start the dlv process in the background
# /root/go/bin/dlv exec --headless --listen localhost:$2 $1
# connect to your local dap server (for dap debugging)
# dlv dap --client-addr=192.168.0.4:4001 --log
# use below to normal debug session
dlv dap --listen=:4001 --api-version=2 exec $1

# dlv --headless=true --allow-non-terminal-interactive=true --disable-aslr=true --listen=0.0.0.0:4001 --accept-multiclient=true --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc --log=true --continue --api-version=2 exec $1
# dlv --headless=true --listen=0.0.0.0:4001 --accept-multiclient --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc --log=true --api-version=2 attach $pid

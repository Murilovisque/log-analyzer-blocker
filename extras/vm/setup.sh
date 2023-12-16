#!/bin/bash


instancia=monitor-blocker
ubuntu_version='205e2453822f'

multipass list | grep -q "${instancia}"
if [[ $? == 0 ]]; then
    multipass start ${instancia}
    multipass mount $(pwd) ${instancia}:/mnt/monitor-blocker
else
    multipass launch ${ubuntu_version} --name ${instancia}  --memory 1G --disk 4G
    multipass list | grep -q "${instancia}"
fi

multipass exec ${instancia} -- sudo apt update
multipass exec ${instancia} -- sudo apt upgrade
multipass exec ${instancia} -- sudo apt install build-essential

# install golang
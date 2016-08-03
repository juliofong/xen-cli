#!/bin/bash
# script name: vm_startup.sh
# copyright emohost.com
# licensed to Julio FONG

SCRIPT=$(basename $BASH_SOURCE)
script_name=$SCRIPT

# kill any running process                                                 
script_pid=$(echo $$)
kill -9 $(ps -ef|grep -v "$script_pid"|grep -v "grep $script_name"|grep "$script_name"|awk '{print $2}') 2>/dev/null

# 1 - start xen daemon
# 2 - start vms by reading file /xen_lists.txt

root_mail=root@localhost
filename=/xen_lists.txt 	# where monitored vm are set


# check if running xen kernel
if echo "$(uname -r)" | grep xen >/dev/null;
then	
	/sbin/service xend start 2>/dev/null
	
else
	echo "$SCRIPT: no running on xen kernel" | tee -a /localhost.log
fi

#

function vm_reboot(){
    local vmname=$(echo $1 | awk '{print $1}') 
    local vmip=$(echo $1 | awk '{print $2}')
    xm reboot "${vmname}" ;
    if [ $? -eq 0 ];
    then
	echo "" >/dev/null
        local msg="vps $1 restarted."
	echo "$SCRIPT: $msg on $(date)." | tee -a /localhost.log
        # mail -s "$msg" "$root_mail" ;
    else
        local msg="vps $1 started."
        echo "$SCRIPT: $msg on $(date)." | tee -a /localhost.log
        xm create "${vmname}".cfg ;
    fi;
}

function start_vm(){
while read line 
do
    name=$(echo $line|grep -o "[a-zA-Z]\{1,10\}"|head -1)
    if [ "$name" != "" ] ; then
	    vm_reboot "$name"
    fi
done < <(cat $filename | grep -v "#[a-zA-Z]\{1,10\}")
}

start_vm

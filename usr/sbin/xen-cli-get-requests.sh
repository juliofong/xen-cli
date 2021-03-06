#!/bin/bash 
#
# Xen CLI (Xen Command Line Interface) 
# Script name : xen-cli-get-requests.sh 
# Description: Get requests for domains creation 
# 
# Please maintain the author name, some usage restrictions apply according to the GPL 
# Author: Julio FONG, juliofong@mail.com 
# Copyright (C) 2016 Julio FONG, GPL V3 
# 
# This program is free software: you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation, either version 3 of the License, or 
# (at your option) any later version. 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
# GNU General Public License for more details. 
# You should have received a copy of the GNU General Public License 
# along with this program.  If not, see <http://www.gnu.org/licenses/>. 

    # include file with functions and variables 
    SCRIPT_DIR=$(readlink -f $0) 
    SCRIPT_DIR=${SCRIPT_DIR%/*} 
    source $SCRIPT_DIR/xe-get-scp.conf 

scp_domain="${scp_domain}/scp" 

# store PID 
# echo $$ >/var/run/xe_get_scp_requests.pid 

# check for required files 
if [ ! -f /etc/xen/xen_manage.sh ] ; then 
echo "xen_manage.sh not found, exiting..."
exit 1 ;
# mail admin
fi 

# store IP into array
iplist_file=/xen_lists.txt
if [ ! -f "$iplist_file" ] ; then
echo "file $iplist_file doesn't exist."
exit 1
# mail admin
fi

check_vm(){
	unset iplist_array
  	while IFS= read line
        do iplist_array+=("$line")
        done < <(cat "$iplist_file" |grep -v "#")
}
check_vm ;

looptime=60
k=0
while true
do
	for (( i=0 ; i<${#iplist_array[@]} ; ++i ))
	do	
		vmip=$(echo ${iplist_array[$i]} |grep -v "#" |awk '{print $2}' |head -1)
		vmname=$(echo ${iplist_array[$i]} |grep -v "#" |awk '{print $1}' |head -1)

		encoded=$(echo -n $vmip |md5sum |tr -d '-' |tr -d ' ')
		cutl=${encoded:0:8}
		cutr=${encoded: -4}
		cutm=$(echo $encoded |sed 's/'$cutl'//g')
		cutm=$(echo $cutm |sed 's/'$cutr'//g')
		filekey="$cutr""$cutm""$cutl"

		# download req file
		reqfile="http://${scp_domain}/reqfile.php?secret_key=${filekey}"

		# check if file exist		
		wget --quiet --spider --timeout=0 --tries=1 ${reqfile}
		if [ $? -eq 0 ] ; then 
			unset req_array 
                        while IFS= read line
                        do req_array+=("$line")
                        done < <(wget "${reqfile}" -q -O -)

			ipone=$vmip
			iptwo=$(echo ${iplist_array[$i]} |grep -v "#" |awk '{print $3}')
	        	otype=${req_array[0]}
	       		osname=${req_array[1]}
        		request=${req_array[2]}
			reqstatus=${req_array[3]}
			lang=${req_array[4]}

			if [ "$reqstatus" == "1" ] ; then
				# make sure another process is not running
				if [ "$request" == "c" ] ; then 
					/etc/xen/xen_manage.sh "$ipone" "$iptwo" "$otype" "$osname" "create" "$reqstatus" "$lang"
				elif [ "$request" == "d" ] ; then 
					/etc/xen/xen_manage.sh "$ipone" "$iptwo" "$otype" "$osname" "delete" "$reqstatus" "$lang"
				elif [ "$request" == "s" ] ; then 
    		        	 	/etc/xen/xen_manage.sh "$ipone" "$iptwo" "$otype" "$osname" "suspend" "$reqstatus" "$lang"
	                        elif [ "$request" == "s0" ] ; then
        	                       	/etc/xen/xen_manage.sh "$ipone" "$iptwo" "$otype" "$osname" "shutdown" "$reqstatus" "$lang"
	                	elif [ "$request" == "s1" ] ; then
        	                	/etc/xen/xen_manage.sh "$ipone" "$iptwo" "$otype" "$osname" "restart" "$reqstatus" "$lang"
				elif [ "$request" == "r" ] ; then 
					/etc/xen/xen_manage.sh "$ipone" "$iptwo" "$otype" "$osname" "reinstall" "$reqstatus" "$lang"
				fi
			fi
		fi
	done

        sleep $looptime
        k=$(($looptime+$k))

        if [ $k -eq 300 ] ; then
	check_vm ;
        k=0
	fi
done

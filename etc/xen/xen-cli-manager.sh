#!/bin/bash 
# 
# Xen CLI (Xen Command Line Interface) 
# script name : xen-cli-manager.sh 
# Description: Command line script for VM management 
# Requirements: Xen v3 
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
# store PID

# /etc/xen/xen-cli-provision.sh "188.40.110.88" "" "xsvps" "freebsd.9-0.x86" "create"
###########################
# ARGS ####################
###########################
# $1: ipone
# $2: iptwo
# $3: offer type
# $4: osname
# $5: create || delete || reinstall || suspend (poweroff)
# $6: lang if set


# include file with functions and variables
source /usr/sbin/xe-get-scp.conf

scpdomain="${scp_domain}/scp"

TIME=$(date +%Y-%m-%d-%H:%M:%S)
LOG=/var/log/scp.log
if [ ! -f $LOG ] ; then
	# echo $TIME "" >>/$LOG
	touch $LOG ;
fi
# 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG

# store IP into array
iplist_file=/xen_lists.txt
if [ ! -f "$iplist_file" ] ; then
echo "file $iplist_file doesn't exist."
exit 1
# mail admin
fi

get_offer(){
        domain=$(cat $iplist_file |grep -v "#" |grep "$1" |awk '{print $1}' |head -1)
        vmcfg=$(grep -l $1 /etc/xen/*.cfg |head -1) ;
        vmcfgname=$(echo $vmcfg |sed 's/\/etc\/xen\///g'|sed 's/.cfg//') ;
        if [ "$domain" == "$vmcfgname" ] ; then
        vmname=$(grep "name.*=.*" $vmcfg |sed 's/name.*=//g' |sed "s/'//g" |sed 's/^ //') ;
        else
        vmcfgname=$domain
        vmname=$domain
        fi

	IFS=

        while read line
        do lvs_array+=("$line")
        done < <(lvs)

        while read line
        do offer_array+=("$line")
        done < <(cat /etc/xen/${vmname}.cfg)

	vmname=$vmname
	vmcpus=$(printf "%s\n" ${offer_array[@]} |grep "vcpus.*=.*" |sed 's/vcpus.*=//g' |sed "s/'//g" |sed 's/^ //')
        vmmemsize=$(printf "%s\n" ${offer_array[@]} |grep "^memory.*=.*" |sed 's/memory.*=//g' |sed "s/'//g" |sed 's/^ //')
        vmdisksize=$(printf "%s\n" ${lvs_array[@]} |grep "${vmname}_img" |awk '{print $4}' |grep -o "[0-9].*\." |tr -d '.')
        vmswapsize=$(printf "%s\n" ${lvs_array[@]} |grep "${vmname}_swap" |awk '{print $4}' |grep -o "[0-9].*\." |tr -d '.')
	
	unset IFS
}

create_vm(){
	echo $TIME "create_vm function started for $1" 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG

	local randompass="$6"

        # check	if create or reinstall
        if [ "$6" == "r" ] ; then
        get_offer "$1"
        fi
	# exit

	domain=$(cat $iplist_file |grep -v "#" |grep "$1" |awk '{print $1}' |head -1)
        vmcfg=$(grep -l $1 /etc/xen/*.cfg |head -1) ;
        vmcfgname=$(echo $vmcfg |sed 's/\/etc\/xen\///g'|sed 's/.cfg//') ;
        if [ "$domain" == "$vmcfgname" ] ; then
        vmname=$(grep "name.*=.*" $vmcfg |sed 's/name.*=//g' |sed "s/'//g" |sed 's/^ //') ;
        else
	vmcfgname=$domain
        vmname=$domain
        fi

	domain=$(cat $iplist_file |grep -v "#" |grep "$1" |awk '{print $1}')
        if [ "$2" == "" ] ; then
	        iptwo=$(cat /etc/xen/${domain}.cfg |grep "vif" |grep -o "ip=.*," |sed 's/ip=//g' |sed 's/,//g' |awk '{print $2}')
		if [ "$iptwo" == "" ] ; then
			iptwo=" " ;
		fi
        fi

        # echo /etc/xen/xen_provision.sh "$1" "$iptwo" "$3" "$4" "$randompass" "$vmcpus" "$vmmemsize" "$vmdisksize" "$vmswapsize" 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG
	# exit
	
        delete_vm "$1" "$2" "$3" "$4" "$5" ;

	if [ "$vmname" == "" ] ; then	
        	/etc/xen/xen_provision.sh "$1" "$iptwo" "$3" "$4" ;
	else
		if [ "$vmcpus" != "" ] && [ "$vmmemsize" != "" ] && [ "$vmdisksize" != "" ] && [ "$vmswapsize" != "" ]; then
			# echo "/etc/xen/xen_provision.sh "$1" "$iptwo" "$3" "$4" "$randompass" "$vmcpus" "$vmmemsize" "$vmdisksize" "$vmswapsize""
			/etc/xen/xen_provision.sh "$1" "$iptwo" "$3" "$4" "$randompass" "$vmcpus" "$vmmemsize" "$vmdisksize" "$vmswapsize" ;
		else
                	/etc/xen/xen_provision.sh "$1" "$iptwo" "$3" "$4" "$randompass" ;
		fi
	fi
}

delete_vm(){ 
	echo $TIME "delete_vm function started for $1" 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG
	# get vm name by searching IP
	# assuming that $1 is main vm IP address 

        domain=$(cat $iplist_file |grep -v "#" |grep "$1" |awk '{print $1}' |head -1)

        vmcfg=$(grep -l $1 /etc/xen/*.cfg |head -1) ;
        vmcfgname=$(echo $vmcfg |sed 's/\/etc\/xen\///g'|sed 's/.cfg//') ;

        if [ "$domain" == "$vmcfgname" ] ; then
        vmname=$(grep "name.*=.*" $vmcfg |sed 's/name.*=//g' |sed "s/'//g" |sed 's/^ //') ;
        else
	vmcfgname=$domain
        vmname=$domain
        fi

	# destroy vm 
	xm destroy $vmname  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG ;

	if [ -f "/etc/xen/${vmname}.cfg" ]; then
		# make sure vmname is found
		# remove vm disks volume
		VG=$(lvs |grep -o "$vmcfgname.*" |awk '{print $2}' |head -1) 
		echo "y" |lvremove "/dev/${VG}/${vmname}_img"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
       	 	echo "y" |lvremove "/dev/${VG}/${vmname}_swap" 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        
		# delete cfg file
		rm -rf "$vmname"".cfg"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG; 
	
		# remove vm info from /xen_lists.txt 
		sed -i 's/^.*'$vmname' .*//g' /xen_lists.txt  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	fi
}

reinstall_vm(){
	echo "reinstall_vm function started for" "$1" 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	create_vm "$1" "$2" "$3" "$4" "$5" "$6"
}

suspend_vm(){
	echo "suspend_vm function started for $1" 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	# get vm name by searching IP
        # assuming that $1 is main vm IP address
        domain=$(cat $iplist_file |grep -v "#" |grep "$1" |awk '{print $1}' |head -1)
        vmcfg=$(grep -l $1 /etc/xen/*.cfg |head -1) ;
        vmcfgname=$(echo $vmcfg |sed 's/\/etc\/xen\///g'|sed 's/.cfg//') ;

        if [ "$domain" == "$vmcfgname" ] ; then
        vmname=$(grep "name.*=.*" $vmcfg |sed 's/name.*=//g' |sed "s/'//g" |sed 's/^ //') ;
        else
        vmcfgname=$domain
        vmname=$domain
        fi

        if [ "$vmname" == "" ]; then
        exit 1
	fi

	xm pause $vmname  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	sed -i 's/^'$vmname'/#'$vmname'/g' /xen_lists.txt  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
}

kill_vm(){
	echo "kill_vm function started for $1" 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        domain=$(cat $iplist_file |grep -v "#" |grep "$1" |awk '{print $1}' |head -1)
        vmcfg=$(grep -l $1 /etc/xen/*.cfg |head -1) ;
        vmcfgname=$(echo $vmcfg |sed 's/\/etc\/xen\///g'|sed 's/.cfg//') ;

        if [ "$domain" == "$vmcfgname" ] ; then
        vmname=$(grep "name.*=.*" $vmcfg |sed 's/name.*=//g' |sed "s/'//g" |sed 's/^ //') ;
        else
        vmcfgname=$domain
        vmname=$domain
        fi

        if [ "$vmname" == "" ]; then
        exit 1
	fi

        xm shutdown $vmname  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	sleep 60 ;

        # make sure vm is not running
        if xm list |grep -v "Name\|Domain" |awk '{print $1}' |grep "$vmname" >/dev/null ; then
	        sleep 60 ;
	        if xm list |grep -v "Name\|Domain" |awk '{print $1}' |grep "$vmname" >/dev/null ; then
       		xm destroy $vmname  2>&1 |eval 'log=$(cat);echo $TIME $log' | tee -a $LOG;
	        fi
        fi
}

shutdown_vm(){
	echo "shutdown_vm function started for $1"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG
	kill_vm "$1" ;
}

restart_vm(){
	echo "restart_vm function started for $1"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG; 
	shutdown_vm $1 ;

	domain=$(cat $iplist_file |grep -v "#" |grep "$1" |awk '{print $1}' |head -1)
        vmcfg=$(grep -l $1 /etc/xen/*.cfg |head -1) ;
        vmcfgname=$(echo $vmcfg |sed 's/\/etc\/xen\///g'|sed 's/.cfg//') ;
        if [ "$domain" == "$vmcfgname" ] ; then
        vmname=$(grep "name.*=.*" $vmcfg |sed 's/name.*=//g' |sed "s/'//g" |sed 's/^ //') ;
        else
	vmcfgname=$domain
        vmname=$domain
        fi

        if [ "$vmname" == "" ]; then
        exit 1
	fi

	xm create "${vmname}.cfg"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
}

manual_select(){
echo "========================================="
echo -e " 'Create|Delete|Suspend A Xen VM : '\n"
echo "#1) 'cv' Create A Custom VM"
echo "#3) 'cc' Create A Centos VM" "*TEST*"
echo "#5) 'dv' Delete A VM"
echo "#7) 'ov' Others" "*TEST*"
echo "========================================="
echo " Choose from below: (enter a number 1,2 or 3) "

sleep 1 ;
select rep in "cv" "" "" "cc" "" "" "dv" "" "ov";
do
    case $rep in
        cv)
            clear
            echo "========================================="
            echo " Running xen_provision.sh script..."
		create_vm 
	 ;;
        cc) 
            clear
            echo "========================================="
            echo " Creating A New Centos VM... ";
            sleep 1;
            echo " What Package ?: cen1(20Gb) cen2(40Gb) cen3(50Gb) cen(custom values)  "
            echo " Type a number to choose or type a letter to go back "
            select ccchoice in "cen1" "cen2_cpanel" "cen3" "cen4" "cen5_emo" "cen6_prod" "cen_custom" "exit" ;
            do
                case $ccchoice in
                    cen1)
                        cpanel="0"
                        cpucores="1"
                        packvps="cen1"
                        sizevps="30"
                        memvps="512"
                        swapvps="1024"
                        centos_creating
                        ;;
                    cen2_cpanel)
                        cpanel="1"
                        packvps="cen2"
                        cpucores="2"
                        sizevps="30"
                        memvps="512"
                        swapvps="1024"
                        centos_creating                    
                        ;;
                    cen3)
                        cpanel="1"
                        packvps="cen3"
                        cpucores="3"
                        sizevps="50"
                        memvps="1024"
                        swapvps="2048"
                        centos_creating                    
                        ;;
                    cen4)
                        cpanel="1"
                        packvps="cen4"
                        cpucores="4"
                        sizevps="70"
                        memvps="2048"
                        swapvps="4096"
                        centos_creating                    
                        ;;
                    cen5_emo)
                        cpanel="1"
                        cpucores="4"
                        packvps="cen5"
                        sizevps="10"
                        memvps="8192"
                        swapvps="4096"
                        centos_creating                    
                        ;;
                    cen6_prod)
                        cpanel="1"
                        cpucores="4"
                        packvps="cen6"
                        sizevps="750"
                        memvps="16384"
                        swapvps="4096"
                        centos_creating                
                        ;;
                    cen_custom)
                        clear
                        echo "enter variables values"
                            packvps="cen"       
                        echo "how many cpu cores?"
                            read cpucores                                        
                        echo "type vps size (Gb)?"
                            read sizevps
                        echo "type memory size (Mb)?"
                            read memvps
                        echo "type swap size (Mb)?"
                            read swapvps
                        centos_creating
                        ;;    
                    back)
                        exit
                        ;;
                    *)
                        echo "Error: enter a number: 1, 2 or 3."
			;;
                esac
            done
         ;;
        dv)
            clear
            echo "================"
            echo -e " * Delete a VPS * \n"
            echo "viewing /xen_lists.txt file:"
            cat /xen_lists.txt
            
            echo "vps name to shutdown ?"
                read vpsname
            echo "viewing /etc/xen/""$vpsname"".cfg file:"  
            cat "/etc/xen/""$vpsname"".cfg"
            xm destroy "$vpsname"
            xm shutdown "$vpsname"
            
            #rm -rf "/data/xen/images/centos_54""$os_type""/""$vpsname"
            #rm -rf "/etc/xen/""$vpsname"".cfg"
            #echo "ip 1 to restore as available ?"
            #    read ipone
            #echo "ip 2 to restore as available ?"
            #    read iptwo
            #sed -i 's/"$ipone"/ /g' /xen_lists.txt
            #sed -i 's/"$iptwo"/ /g' /xen_lists.txt
            #echo "$ipone" >> /data/xen/domains/ip_lists.txt
            #echo "$iptwo" >> /data/xen/domains/ip_lists.txt
            #nano /xen_lists.txt
            lvremove /dev/vgu/"$vpsname"_img;
            lvremove /dev/vgu/"$vpsname"_swap;
            sed -i "s/"$vpsname".*/ /g" /xen_lists.txt ;
            echo "VPS removed."
            updatedb
         ;;
         *)
            echo "Error: enter a number: 1, 2 or 3."
	 ;;
        ov)
            clear
         ;;    
    esac
done

}

#######################################
# run manual selection if $1 is not set
if [ "$1" == "" ] ; then
	manual_select
else
	# check for valid requests before starting
	tmp_key=$(echo -n $1 |sha256sum |tr -d "-" |tr -d " ")

	content=$(wget "http://${scpdomain}/reqcheck.php?tmp_key=${tmp_key}&ip=${ip}" -q -O -)
        if [ "$content" -ne 1 ] ; then
		echo "xen_manage.sh exited on wget reqcheck.php not equal 1 req ip=${ip}" 2>&1 |eval 'log=$(cat);echo $TIME $log' >>$LOG
                exit 1
        fi

	randompass=$(cat /dev/urandom| tr -dc 'a-zA-Z0-9' | fold -w 12| head -1)

	if [ "$6" == "1" ] ; then
		if [ "$5" == "create" ] ; then
        		create_vm "$1" "$2" "$3" "$4" "$5" "$randompass" 
			five="c"
		elif [ "$5" == "delete" ] ; then
        		delete_vm "$1" "$2" "$3" "$4" "$5"
        		five="d"
		elif [ "$5" == "reinstall" ] ; then
        		reinstall_vm "$1" "$2" "$3" "$4" "$5" "$randompass"
        		five="r"
		elif [ "$5" == "suspend" ] ; then
        		suspend_vm "$1" "$2" "$3" "$4" "$5"
			five="s"
		elif [ "$5" == "shutdown" ] ; then
        		shutdown_vm "$1" "$2" "$3" "$4" "$5"
        		five="s0"
		elif [ "$5" == "restart" ] ; then
        		restart_vm "$1" "$2" "$3" "$4" "$5"
        		five="s1"
		fi
	fi

	# update ip_reqstatus.php if $6 is set
	if [ "$6" == "1" ] ; then
		lang=$7
		# set job to status 0 wget to remove stored req file
		wget --quiet --spider --timeout=0 --tries=1 "http://"${scpdomain}"/reqstatus.php?ipone="$1"&req=${five}&status=0&tmp_key=${tmp_key}&os="$4"&lang=${lang}&passwd=${randompass}"
		# echo "http://"${scpdomain}"/reqstatus.php?ipone="$1"&req=${five}&status=0&tmp_key=${tmp_key}&os="$4"&lang=${lang}&passwd=${randompass}" >>/var/log/scp.log
	fi
fi

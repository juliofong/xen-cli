#!/bin/bash 
# 
# Xen CLI (Xen Command Line Interface) 
# Script name : xen-cli-get-guest-stats.sh
# Description: Get Xen guests stats 
# 
# Please maintain the author name, some usage restrictions apply according to the GPL 
# Author: Julio FONG, juliofong@mail.com 
# Copyright (C) 2016 Julio FONG, GPL V3 
# 
# This program is free software: you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation, either version 3 of the License, or 
# (at your option) any later version. 
# 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
# GNU General Public License for more details. 
# 
# You should have received a copy of the GNU General Public License 
# along with this program.  If not, see <http://www.gnu.org/licenses/>. 

    # include file with functions and variables 
    SCRIPT_DIR=$(readlink -f $0) 
    SCRIPT_DIR=${SCRIPT_DIR%/*} 
    source $SCRIPT_DIR/xe-get-scp.conf 

scpdomain="${scp_domain}/scp" 

check_vm(){ 
        unset xm_array
        while read line
        do
	xm_array+=("$line")
        done < <(xm list | grep -v "Domain\|Name")

	unset ip_array
	# declare -a ip_array
	for (( i=0 ; i<${#xm_array[@]} ; ++i ))
	do
	domain=$( echo ${xm_array[$i]} | awk '{print $1}' )
	# echo $( cat /etc/xen/${domain}.cfg | grep "vif" | grep -o "ip=.*," | sed 's/ip=//g' | sed 's/,//g' | awk '{print $1}' )
	ip_array[$i]="$( cat /etc/xen/${domain}.cfg | grep "vif" | grep -o "ip=.*," | sed 's/ip=//g' | sed 's/,//g' | awk '{print $1}' )"
	done

	# prevent for infinite loop
	if [ "${#xm_array[0]}" == "" ] ; then
		#echo "prevent for infinite loop"
		sleep 60
		check_vm
	fi
}
check_vm

testvar=""
looptime=60
k=1

for (( j=1 ; j<=${looptime} ; ++j ))
do
	#echo $j

	# global ifconfig array
	unset ifconfig_array
        while IFS= read line
        do
	ifconfig_array+=("$line")
        done < <(ifconfig)

        # global xenstore array
        unset xenstore_array
        while IFS= read line
        do
	xenstore_array+=("$line")
        done < <(xenstore-ls)

	# check for running vm
	# check if new vm has been started
	n_vm=$(printf "%s\n" "${xm_array[$i]}"|wc -l)
	n_vif=$(printf "%s\n" "${ifconfig_array[$i]}"|grep vif|wc -l)
	if [ $n_vif -gt $n_vm ] ; then
		check_vm ;
	fi
	
	# check if vm has been shutted down
        for (( i=0 ; i<${#xm_array[@]} ; ++i ))
        do
		id=$(printf "%s\n" "${xm_array[$i]}" | awk '{print $2}')
		iface="vif""$id"".0" ;
        	if ! printf "%s\n" "${ifconfig_array[@]}" |grep "$iface" >/dev/null ; then
			#echo "check_vm restarted"
			check_vm ;
		fi
	done

	#echo "loop_vm $j" 
	##############
	# loop vm
	###############
	for (( i=0 ; i<${#xm_array[@]} ; ++i ))
	do

	id=$(printf "%s\n" "${xm_array[$i]}" | awk '{print $2}')

        # array for current id
        unset xsid_array
        while IFS= read line
        do
        xsid_array+=("$line")
        done < <(printf "%s\n" "${xenstore_array[@]}" |awk '/^      backend = "\/local\/domain\/0\/backend\/vif\/'${id}'\/0"/{f=1;next}f')
	
	# resources vars
        resources=$(printf "%s\n" "${xsid_array[@]}" |grep -o "resources.*" |head -1)
        space=$(printf "%s\n" "${xsid_array[@]}" |grep -o "space.*" |head -1)
        availability=$(printf "%s\n" "${xsid_array[@]}" |grep -o "availability.*" |head -1)

	##############################################################
	# resources
	#
	ncores=0
        # in %
        procusage=$(echo $resources |sed 's/-/ /g' |sed 's/"/ /g' |awk '{print $4}')
        # in k
        memtotal=$(echo $resources |sed 's/-/ /g' |sed 's/"/ /g' |awk '{print $6}')
        memused=$(echo $resources |sed 's/-/ /g' |sed 's/"/ /g' |awk '{print $7}')
        swaptotal=$(echo $resources |sed 's/-/ /g' |sed 's/"/ /g' |awk '{print $8}')
        swapused=$(echo $resources |sed 's/-/ /g' |sed 's/"/ /g' |awk '{print $9}')
        r_statistic="ncoresE${ncores}AprocusageE${procusage}AmemtotalE${memtotal}AmemusedE${memused}AswaptotalE${swaptotal}AswapusedE${swapused}"

	# echo $procusage
	# echo $r_statistic

	#############################################################
	# traffic
	#
        iface="vif""$id"".0" ;
        ipaddr=${ip_array[$i]}

	#echo $iface
	#echo $ipaddr

        incoming[$i]=$(printf "%s\n" "${ifconfig_array[@]}" |awk '$1=="'$iface'"' RS='' |grep -o "TX.*)" |grep -o "[0-9].*$" |awk '{print $1}')
        outgoing[$i]=$(printf "%s\n" "${ifconfig_array[@]}" |awk '$1=="'$iface'"' RS='' |grep -o "RX.*)" |grep -o "[0-9].*$" |awk '{print $1}')

	#if [ "${testvar[$i]}" == "" ] ; then
	#testvar[$i]="${incoming[$i]}"
	#fi
	#echo "in=${testvar[$i]}"
	
        if [ "${out_dif_sec[$i]}" == "" ]; then out_dif_sec[$i]=0 ; fi
        if [ "${in_dif_sec[$i]}" == "" ]; then in_dif_sec[$i]=0 ; fi
        # return outgoing traffic dif per sec
        if [ "${out_store[$i]}" != "" ] ; then
        out_dif_sec[$i]=`expr ${outgoing[$i]} - ${out_store[$i]}`
        in_dif_sec[$i]=`expr ${incoming[$i]} - ${in_store[$i]}`
        fi

        if [ "${totalout[$i]}" == "" ]; then totalout[$i]=0 ; totalin[$i]=0 ; fi
        totalout[$i]=`expr ${out_dif_sec[$i]} + ${totalout[$i]}`
        totalin[$i]=`expr ${in_dif_sec[$i]} + ${totalin[$i]}`

        # update or initialise
        out_store[$i]=${outgoing[$i]}
        in_store[$i]=${incoming[$i]}

        # return total traffic dif per time interval (min or hour)

        if [ "${out_store_mn[$i]}" == "" ] ; then
        out_store_mn[$i]=${outgoing[$i]}
        in_store_mn[$i]=${incoming[$i]}
        fi

        if [ "${out_dif_mn[$i]}" == "" ]; then out_dif_mn[$i]=0 ; fi
        if [ "${in_dif_mn[$i]}" == "" ]; then in_dif_mn[$i]=0 ; fi

        if (( $j == $looptime )) ; then
                out_dif_mn[$i]=`expr ${outgoing[$i]} - ${out_store_mn[$i]}`
                in_dif_mn[$i]=`expr ${incoming[$i]} - ${in_store_mn[$i]}`
                # update
                out_store_mn[$i]=${outgoing[$i]}
                in_store_mn[$i]=${incoming[$i]}
		#echo out_dif_mn		${out_dif_mn[$i]}
		#echo in_dif_mn		${in_dif_mn[$i]}
        fi

        if [ "$countd" == "$looptime" ] ; then 
t_statistic="totaloutE${totalout[$i]}AtotalinE${totalin[$i]}ArouteoutdifE${out_dif_sec[$i]}ArouteindifE${in_dif_sec[$i]}ArouteoutdifmnE${out_dif_mn[$i]}ArouteindifmnE${in_dif_mn[$i]}AipE${ipaddr}"
        else
	t_statistic="totaloutE0AtotalinE0ArouteoutdifE${out_dif_sec[$i]}ArouteindifE${in_dif_sec[$i]}ArouteoutdifmnE0ArouteindifmnE0AipE${ipaddr}"
        fi

	#echo ""
	#echo totaloutE	${totalout[$i]}
	#echo totalinE	${totalin[$i]}
        #echo outdifE	${out_dif_sec[$i]}
	#echo indifE	${in_dif_sec[$i]}
	
#t_statistic="totaloutE${totalout[$i]}AtotalinE${totalin[$i]}ArouteoutdifE${out_dif_sec[$i]}ArouteindifE${in_dif_sec[$i]}ArouteoutdifmnE${out_dif_mn[$i]}ArouteindifmnE${in_dif_mn[$i]}AipE${ipaddr}"
	# t_statistic="totaloutE${totalout}AtotalinE${totalin}AoutdifE${out_dif_sec}AindifE${in_dif_sec}AoutdifmnE${out_dif_mn}AindifmnE${in_dif_mn}AipE${ipaddr}"
	# echo out:${out_dif_sec[$i]} in:${in_dif_sec[$i]} outmn:${out_dif_mn[$i]} inmn:${in_dif_mn[$i]} toto:${totalout[$i]} toti:${totalin[$i]}

	############################################################
	# disk
	#
	totalspace=$(echo $space |sed 's/-/ /g' |sed 's/"/ /g' |awk '{print $3}')
        usedspace=$(echo $space |sed 's/-/ /g' |sed 's/"/ /g' |awk '{print $4}')
        freespace=`expr $totalspace - $usedspace`
	rootstats="totalspaceE${totalspace}AusedspaceE${usedspace}"
	diskstats="rootstats=${rootstats}"
	d_statistic=$diskstats
        
	if [ "${tmp_outdifmn[$i]}" == "" ]; then
		tmp_outdifmn[$i]=0        
		tmp_indifmn[$i]=0
        fi

	tmp_statistic="tmp_outdifmnE${tmp_outdifmn[$i]}Atmp_indifmnE${tmp_indifmn[$i]}"
	t_statistic="${tmp_statistic}A${t_statistic}"

	#echo "in_sec  =""${in_dif_sec[$i]}"
	#echo "total_in=""${totalin[$i]}"
	#echo "${t_statistic}"
	#echo "-------------------------------------------------------------------"
	#echo "r_stats=${r_statistic}&t_stats=${t_statistic}&d_stats=${d_statistic}"

	wget --quiet --spider --timeout=1 --tries=1 "http://${scpdomain}/generate.php?r_stats=${r_statistic}&t_stats=${t_statistic}&d_stats=${d_statistic}"	
	#echo "http://${scpdomain}/generate.php?r_stats=${r_statistic}&t_stats=${t_statistic}&d_stats=${d_statistic}"
	#set tmp array if url is not working
	if [[ $? -ne 0 ]]; then
		tmp_outdifmn[$i]=`expr ${out_dif_sec[$i]} + ${tmp_outdifmn[$i]}`
                tmp_indifmn[$i]=`expr ${in_dif_sec[$i]} + ${tmp_indifmn[$i]}`
		tmp_statistic="tmp_outdifmnE${tmp_outdifmn[$i]}Atmp_indifmnE${tmp_indifmn[$i]}"
	else
		tmp_outdifmn[$i]=0
		tmp_indifmn[$i]=0
	fi

	done
	#

	sleep 1

	# reset loop
        if [ $j == $looptime ] ; then
        j=1
        fi

        countd=$((++k))
        if [ "$countd" == "$looptime" ] ; then
	k=1
      	check_vm
        fi
done

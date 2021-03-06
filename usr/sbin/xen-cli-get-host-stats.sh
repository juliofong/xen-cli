#!/bin/bash 
#
# Xen CLI (Xen Command Line Interface) 
# Script name : xen-cli-get-host-stats.sh
# Description: Get Xen host stats for dom0 
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

scpdomain="${scp_domain}/scp"

# 3# disk stats is refreshed every minute
# 2# traffic stats every sec
# 1# all other resources stats every sec

#ncores=$(nproc)
ncores=$(cat /proc/cpuinfo | grep cores | awk '{SUM += $4} END {print SUM}')

if ! cat /etc/resolv.conf |grep "emohost.com - imageinstaller" >/dev/null ;
then exit 1 ;
fi ;

sleep=1

if vmstat $sleep -n 2 | grep "us sy id wa st" >/dev/null ; then
vmtype=1
else
vmtype=2
fi

if cat /etc/issue |grep "GNU\|Debian\|Ubuntu" >/dev/null ; then
distrib=gnulinux
else
distrib=linux
fi

k=1
looptime=60
for (( j=1 ; j<=$looptime ; ++j ))
do
	 #######################################################################
	# route stats #								#
	 #######################################################################
	sleep=1

        function r_stats(){
	# sleep is included
        # resources stats : cpu - mem - swap
        # fetch command result into var and array
        vmstats=$(vmstat $sleep -n 2 |tail -1)
        unset freearray
        while read line
        do
        freearray+=("$line")
        done < <(free | grep -v "total")
        # in %
        procusage=$(echo $vmstats |awk '{print $13+$14}')
        # in k
        memtotal=$(printf "%s\n" "${freearray[@]}" |grep "Mem" |grep -o "[0-9].*" |awk '{print $1}')
        memused=$(printf "%s\n" "${freearray[@]}" |grep "Mem" |grep -o "[0-9].*" |awk '{print $2}')
        swaptotal=$(printf "%s\n" "${freearray[@]}" |grep "Swap" |grep -o "[0-9].*" |awk '{print $1}')
        swapused=$(printf "%s\n" "${freearray[@]}" |grep "Swap" |grep -o "[0-9].*" |awk '{print $2}')

        r_statistic="ncoresE${ncores}AprocusageE${procusage}AmemtotalE${memtotal}AmemusedE${memused}AswaptotalE${swaptotal}AswapusedE${swapused}"
        # end of function
        }

	function rstats(){
	# resources stats : cpu - mem - swap
	declare -a toparray
	# fetch command result into an array
	while read line
	do
	toparray+=("$line")
	done < <(top -n 1 |grep -v "Tasks\|Cpu\|PID\|0.0  0.0")
	# in %
	procusage=$(printf "%s\n" "${toparray[@]}" |grep -v "top\|Mem\|Swap"|awk '{print $10}' |awk '{sum+=$1}END{print sum}')
	# in %
	memusage=$(printf "%s\n" "${toparray[@]}" |grep -v "top\|Mem\|Swap" |awk '{print $11}' |awk '{sum+=$1}END{print sum}')
	# in k
	memtotal=$(printf "%s\n" "${toparray[@]}"|grep -o "Mem:.*total" |sed 's/Mem:\|total\|k//g' |tr -d ' ')
	memused=$(printf "%s\n" "${toparray[@]}" |grep "Mem" |grep -o "total.*used" |sed 's/total\|used\|k\|,//g' |tr -d ' ')
	swaptotal=$(printf "%s\n" "${toparray[@]}" |grep -o "Swap.*total" |sed 's/Swap\|total\|k\|://g' |tr -d ' ')
	swapused=$(printf "%s\n" "${toparray[@]}" |grep "Swap" |grep -o "total.*used" |sed 's/total\|used\|k\|,//g' |tr -d ' ')
	# routestats="procusage=${procusage}&procesusmem=${memusage}&memtotal=${memtotal}&memused=${memused}&swaptotal=${swaptotal}&swapused=${swapused}"
	# echo "procusage=${procusage}&procesusmem=${memusage}&memtotal=${memtotal}&memused=${memused}&swaptotal=${swaptotal}&swapused=${swapused}"
        # end of function
        }

	function t_stats(){
	# traffic stats : in - out
	##########################
        iface="eth0" ;  # just do "ifconfig" for guests
        unset globicfg
        while read line
        do globicfg+=("$line")
        done < <(ifconfig $iface)

	ipaddr=$(printf "%s\n" "${globicfg[@]}" | grep inet |cut -f2 -d ":" |cut -f1 -d " " | head -1)

        incoming=$(printf "%s\n" "${globicfg[@]}" |awk '$1=="'$iface'"' RS='' |grep -o "RX.*)" |grep -o "[0-9].*$" |awk '{print $1}')
        outgoing=$(printf "%s\n" "${globicfg[@]}" |awk '$1=="'$iface'"' RS='' |grep -o "TX.*)" |grep -o "[0-9].*$" |awk '{print $1}')

        if [ "$out_dif_sec" == "" ]; then out_dif_sec=0 ; fi
        if [ "$in_dif_sec" == "" ]; then in_dif_sec=0 ; fi
        # return outgoing traffic dif per sec
        if [ "$out_store_sec" != "" ] ; then
        out_dif_sec=$(($outgoing-$out_store_sec))
        in_dif_sec=$(($incoming-$in_store_sec))
        fi

	if [ "$totalout" == "" ]; then totalout=0 ; totalin=0 ; fi
	totalout=$(( $out_dif_sec+$totalout ))
	totalin=$(( $in_dif_sec+$totalin ))

        # update
        out_store_sec=$outgoing
        in_store_sec=$incoming

	# return total traffic dif per time interval (min or hour)
        # initialise minute array
        if [ "$out_store_mn" == "" ] ; then
        out_store_mn=$outgoing
	in_store_mn=$incoming
        fi

        if [ "$out_dif_mn" == "" ]; then out_dif_mn=0 ; fi
        if [ "$in_dif_mn" == "" ]; then in_dif_mn=0 ; fi
        if (( $j == $looptime )) ; then
                out_dif_mn=$(($outgoing-$out_store_mn))
                in_dif_mn=$(($incoming-$in_store_mn))
                # update
                out_store_mn=$outgoing
		in_store_mn=$incoming
        fi

	if [ "$countd" == "$looptime" ] ; then
	t_statistic="totaloutE${totalout}AtotalinE${totalin}ArouteoutdifE${out_dif_sec}ArouteindifE${in_dif_sec}ArouteoutdifmnE${out_dif_mn}ArouteindifmnE${in_dif_mn}AipE${ipaddr}"
	else
        t_statistic="totaloutE0AtotalinE0ArouteoutdifE${out_dif_sec}ArouteindifE${in_dif_sec}ArouteoutdifmnE0ArouteindifmnE0AipE${ipaddr}"
	fi
	# end of function
	}


	#######################################################################
	function d_stats(){
	# disk stats : rootstats[df stats of each device with path /] - swapstats - dfstats[stats of each device] - vgstats

	declare -a dfval ; # all filesystem partitions values in an array
	declare -a vgval ; # all vg partitions in an array

        # => partname size used avail use% mountedon
	while read line
	do dfval+=("$line")
        done < <(df | grep -v 'Filesystem\|media\|cdrom\|_' | grep "^/dev" | sed 's/%//g')

        # => totalspace usedspace freespace freespace(%)
        dfvaltotal=$(printf "%s\n" "${dfval[@]}" | awk '{sum2+=$2;sum3+=$3;sum4+=$4;sum5+=$5} END {print sum2" "sum3" "sum4" "sum5}')
	# => partname size used
	swapval=$(swapon -s | grep -v "^Filename" | awk '{print $1" "$3" "$4}')

	# define disk stats variable
	diskstats=""

	###
	declare -a dfnewarray
        for (( i=0 ; i<${#dfval[@]} ; ++i ))
        do
        dfline=${dfval[$i]}
        partname=$(echo $dfline | awk '{print $1}')
        partsize=$(echo $dfline | awk '{print $2}')
        partused=$(echo $dfline | awk '{print $3}')
        dfnewarray+=("partnameE${partname}ApartsizeE${partsize}ApartusedE${partused}_")
        done

        for item in "${dfnewarray[*]}"; do
        dfoneline=$(echo $item | tr -d ' ')
        done
	###

	###
	totalspace=$(echo $dfvaltotal | awk '{print $1}')
	usedspace=$(echo $dfvaltotal | awk '{print $2}')
	freespace=$(echo $dfvaltotal | awk '{print $3}')
	rootstats="totalspaceE${totalspace}AusedspaceE${usedspace}"
	###

	#
 	swapname=$(echo $swapval | awk '{print $1}')
        swapsize=$(echo $swapval | awk '{print $2}')
        swapused=$(echo $swapval | awk '{print $3}')
	swapstats="swapnameE${swapname}AswapsizeE${swapsize}AswapusedE${swapused}"
	#

	# if using lvm - /dev/mapper/vgname
        declare -a vgnewarray
	if /bin/df -h | grep "mapper" >/dev/null ; then
		#
        	# => vgname vsize vfree
		while read line
	        do vgval+=("$line")
		done < <(vgs | grep -v 'VG' | sed 's/[0-9]g//g' | awk '{print $1" "$6" "$7}')
		for (( i=0 ; i<${#vgval[@]} ; ++i ))
		do
	        vgline=${vgval[$i]}
	        vgname=$(echo $vgline | awk '{print $1}')
		vgsize=$(echo $vgline | awk '{print $2}')
		vgfree=$(echo $vgline | awk '{print $3}')
		#vgnewarray[$i]=""
                vgnewarray[$i]="vgnameE${vgname}AvgsizeE${vgsize}AvgfreeE${vgfree}_"
		done
		for item in ${vgnewarray[*]};
		do
			# echoes one line containing all elements
	   		vgoneline=$(echo $item | tr -d ' ')
		done
		#

	diskstats="rootstats=${rootstats}Sswapstats=${swapstats}Sdfstats=${dfoneline}Svgstats=${vgoneline}"
	else
	diskstats="rootstats=${rootstats}Sswapstats=${swapstats}Sdfstats=${dfoneline}"
	fi ;
	d_statistic=$diskstats
	# end of function
	}

	r_stats
	t_stats
	d_stats

        if [ "${tmp_outdifmn}" == "" ]; then
		#echo "outdifmn started"
                tmp_outdifmn=0
                tmp_indifmn=0
        fi

	#echo $j
	#echo ${tmp_outdifmn} ${out_dif_sec}
	#echo ${tmp_indifmn} ${in_dif_sec}

        tmp_statistic="tmp_outdifmnE${tmp_outdifmn}Atmp_indifmnE${tmp_indifmn}"
        t_statistic="${tmp_statistic}A${t_statistic}"

	#echo $r_statistic
	#echo $t_statistic
	#echo $d_statistic

	wget --quiet --spider --timeout=1 --tries=1 "http://${scpdomain}/generate.php?r_stats=${r_statistic}&t_stats=${t_statistic}&d_stats=${d_statistic}"
	#echo "http://${scpdomain}/generate.php?r_stats=${r_statistic}&t_stats=${t_statistic}&d_stats=${d_statistic}"
        #set tmp array if url is not working #
        if [[ $? -ne 0 ]]; then
		#echo a
                tmp_outdifmn=`expr ${out_dif_sec} + ${tmp_outdifmn}`
                tmp_indifmn=`expr ${in_dif_sec} + ${tmp_indifmn}`
                tmp_statistic="tmp_outdifmnE${tmp_outdifmn}Atmp_indifmnE${tmp_indifmn}"
		#echo $tmp_statistic
        else
		#echo b
                tmp_outdifmn=0
                tmp_indifmn=0
        fi

        # reset sec if limit is exceeded
        if (( $j == $looptime )); then
        j=1
	fi

	countd=$((++k))
        if [ "$countd" == "$looptime" ] ; then
        k=1
        fi

# end of main loop
done ;

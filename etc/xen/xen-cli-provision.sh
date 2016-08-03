#!/bin/bash 
# 
# Xen CLI (Xen Command Line Interface)  
# script name : xen-cli-provision.sh 
# Description: virtual machines script creation  
# Requirements: Xen v3, LVM (Logical Volume Manager), UFS Module for Unix 
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

# Url to VM images 
osurl=http://78.47.217.22/~emohost/stacklet_img/img

# Ufs module is needed for Bsd distributions

LOG=/var/log/xen-cli.log

#check_args(){
echo $1 >> $LOG
echo $2 >> $LOG
echo $3 >> $LOG
echo $4  >> $LOG
echo $5 >> $LOG
echo $6  >> $LOG
echo $7  >> $LOG
echo $8  >> $LOG
echo $9  >> $LOG
# exit
#}

TIME=$(date +%Y-%m-%d-%H:%M:%S)
LOG=/var/log/xen-cli.log
if [ ! -f $LOG ] ; then
        # echo $TIME "" >>/$LOG
        touch $LOG ;
fi
# 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG

# /etc/xen/xen_provision.sh "188.40.110.88" "" "xsvps" "arch.2013-01.x86-64" 
# check if args are used else prompt to enter values
# $1 : main ip 
# $2 : second ip
# $3 : xsvps,svps...
# $4 : centos.5-8,...
# if from xen-cli manage requests
# $5 : password
# $6 : cpus
# $7 : mem size
# $8 : disk size
# $9 : swap size

ipone=$1
iptwo=$2

if [ "$6" != "" ] ; then
	option="custom"
else
	if [ "$3" == "xsvps" ] ; then
	option="a"
	elif [ "$3" == "svps" ] ; then
	option="b"
	elif [ "$3" == "mvps" ] ; then
	option="c"
	elif [ "$3" == "lvps" ] ; then
	option="d"
	fi
fi
oschoice=$4
newpasswd=$5

#
VG=vg0

idir="/install_dir"
osdir="/xen_os" ; # mount /dev/$VG/xen_os /xen_os # else use non mounted folder
ospart=$( lvdisplay | grep "xen_os" | awk '{print $3}' | head -1 )
# TMP VALUES
osdir="/xen_os_done"
ospart="/dev/vg0/xen_img_done"

xenv=$(find /usr/share/doc/ -name "xen*" | head -1 | sed 's/\/usr\/share\/doc\///g')
if echo "$xenv" | grep "3" >/dev/null ; then xv=3
elif echo "$xenv" | grep "4" >/dev/null ; then xv=4 ;
fi ;
echo "found xen version $xenv : starting script for xen versions $xv..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG
sleep 3

#needed for netbsd dom0 kernel download
#if cat /proc/cpuinfo | grep "Intel" >/dev/null ; then
#cpumodel=intel
#elif cat /proc/cpuinfo | grep "AMD" >/dev/null ; then
#cpumodel=amd
#fi ;

# NETBSD variables
# needed for netbsd dom0 kernel download
if echo $(arch) | grep "x86" >/dev/null ; then
cpumodel=i386
elif echo $(arch) | grep "x86_64" >/dev/null ; then
cpumodel=amd64
fi ;

declare -a oseslist=( \
"archlinux.2013-01.x86-64.20121230.img.tar.bz2" \
"centos.5-8.x86.20120308.img.tar.bz2" \
"centos.5-8.x86-64.20120308.img.tar.bz2" \
"centos.5-9.x86.20130118.img.tar.bz2" \
"centos.5-9.x86-64.20130118.img.tar.bz2" \
"centos.6-2.x86.20111220.img.tar.bz2" \
"centos.6-2.x86-64.20111220.img.tar.bz2" \
"centos.6-3.x86.20120709.img.tar.bz2" \
"centos.6-3.x86-64.20120709.img.tar.bz2" \
"centos.6-4.x86.20130309.img.tar.bz2" \
"centos.6-4.x86-64.20130309.img.tar.bz2" \
"centos.6-4.x86.cpanel.20130309.img.tar.bz2" \
"centos.6-4.x86-64.cpanel.20130309.img.tar.bz2" \
"cloudlinux.5-7.x86-64.20120219.img.tar.bz2" \
"cloudlinux.6-4.x86-64.20130317.img.tar.bz2" \
"debian.5-0.x86.20111003.img.tar.bz2" \
"debian.5-0.x86-64.20111003.img.tar.bz2" \
"debian.6-0.x86.20111008.img.tar.bz2" \
"debian.6-0.x86-64.20111008.img.tar.bz2" \
"fedora.16.x86.20111230.img.tar.bz2" \
"fedora.16.x86-64.20111230.img.tar.bz2" \
"fedora.17.x86.20120529.img.tar.bz2" \
"fedora.17.x86-64.20120529.img.tar.bz2" \
"fedora.18.x86.20130116.img.tar.bz2" \
"fedora.18.x86-64.20130116.img.tar.bz2" \
"freebsd.8-3.x86.20120401.img.tar.bz2" \
"freebsd.8-3.x86-64.20120401.img.tar.bz2" \
"freebsd.9-0.x86.20120101.img.tar.bz2" \
"freebsd.9-0.x86-64.20120101.img.tar.bz2" \
"gentoo.2013-01.x86-64.20130102.img.tar.bz2" \
"netbsd.5-2.x86.20130101.img.tar.bz2" \
"netbsd.5-2.x86-64.20130101.img.tar.bz2" \
"netbsd.6-0.x86.20121022.img.tar.bz2" \
"netbsd.6-0.x86-64.20121022.img.tar.bz2" \
"opensolaris.20090601.x86.img.tar.bz2" \
"opensuse.12-2.x86.20120904.img.tar.bz2" \
"opensuse.12-2.x86-64.20120904.img.tar.bz2" \
"ubuntu.10-04.x86.20120725.img.tar.bz2" \
"ubuntu.10-04.x86-64.20120725.img.tar.bz2" \
"ubuntu.12-04.x86.20130211.img.tar.bz2" \
"ubuntu.12-04.x86-64.20130211.img.tar.bz2" \
"ubuntu.12-10.x86.20121017.img.tar.bz2" \
"ubuntu.12-10.x86-64.20121017.img.tar.bz2" \
"ubuntu.13-04.x86.20130501.img.tar.bz2" \
"ubuntu.13-04.x86-64.20130501.img.tar.bz2" \
)

touch /xen_lists.txt 2>/dev/null;
hexchars="0123456789ABCDEF"
end=$( for i in {1..6} ; do echo -n ${hexchars:$(( $RANDOM % 16 )):1} ; done | sed -e 's/\(..\)/:\1/g' )
macaddr="00:16:3E""$end"

# check for duplicated vm names
declare -a vmname_array=( "lvdisplay | grep 'vm.*img' | awk '{print $3}' | sed 's/\/dev\/'$VG'\///g')" )
for i in {1..10};
do
  	if ! /usr/sbin/lvdisplay | grep 'vm.*img' | grep $i >/dev/null ; then
        vmname="vm"$i
	vmid=$i
        break ;
        fi ;
done ;
 
function get_netmask(){
        cat /etc/sysconfig/network-scripts/ifcfg-eth0 | grep "NETMASK" | sed 's/NETMASK=//g' | head -1 ;
}
# XXX.XXX.XXX.0
netmask=$(get_netmask |sed 's/\.[0-9]*$/.0/')
bdcast=$( cat /etc/sysconfig/network-scripts/ifcfg-eth0 | grep "BROADCAST" | sed 's/BROADCAST=//g' | head -1 ) ;

function get_mainip(){
    local OS=`uname`
    local IO="" # store IP
    case $OS in
       Linux) local IP=`ifconfig | grep 'inet addr:'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{print $1}'` ;;
       FreeBSD|OpenBSD) local IP=`ifconfig  | grep -E 'inet.[0-9]' | grep -v '127.0.0.1' | awk '{print $2}'` ;;
       SunOS) local IP=`ifconfig -a | grep inet | grep -v '127.0.0.1' | awk '{print $2} '` ;;
       *) local IP="Unknown" ;;
    esac ;
    echo "$IP" ;
}
declare -a mainips_array=( $(get_mainip) );
mainip=${mainips_array[0]}

if echo "$osfile" | grep "bsd" >/dev/null ; then
  # check if ufs is loaded
  if /sbin/modprobe ufs | grep "not found" >/dev/null ; then
    #wget -P "$osdir" "$kmodurl" ;
    #if [ $? -ne 0 ]; then
    #    echo "please correct kmod download package url."
    #    exit ;
    #else
    #    rpm -ivh "$osdir"/kmod-ufs-xen-*.elrepo.$(arch).rpm ;
    #    /sbin/modprobe ufs ;
    #fi ;
    echo "module ufs not found in kernel." ;
    install_bsd=0
  fi ;
fi;


function inst(){

    # $1 is os name
    local osfile=${oseslist[$1]}

    netbsdv=$( echo $osfile |sed 's/.x86.*//g' |sed 's/x86.*//g'| sed 's/netbsd\.//g' |sed 's/\./-/g' )
    freebsdv=$( echo $osfile |sed 's/.x86.*//g' |sed 's/x86.*//g'| sed 's/freebsd\.//g' |sed 's/\./-/g' )
    netbsdkernelurl="http://ftp.netbsd.org/pub/NetBSD/NetBSD-${netbsdv}/${cpumodel}/binary/kernel/netbsd-XEN${xv}_DOMU.gz"

    #osname=$( echo "$osfile" | sed 's/\.[0-9]\{5,15\}//g' | sed 's/.img.tar.bz2//g' | sed 's/.img.tar.gz//g' | sed 's/.img.tar//g' )
    osname=$( echo "$osfile" |sed 's/.img.tar.bz2//g' |sed 's/.img.tar.gz//g' |sed 's/.img.tar//g' )
    umount "$osdir"/tmp  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
 
    mkdir "$osdir" 2>/dev/null 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
    mount "$ospart" "$osdir" 2>/dev/null 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
 
    # download os image
    if [ ! -f "$osdir"/"$osfile" ]; then
    echo "downloading $osfile file ..."
        sleep 4 ;
        wget -P "$osdir" "$osurl"/"$osfile" ;
        if [ $? -ne 0 ]; then
        echo "download file not found."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG
        exit ;
	fi ;
    fi ;

    # extract
    # rm -rf "$osdir"/tmp 2>/dev/null ;
    mkdir "$osdir"/tmp 2>/dev/null ;
    echo "extracting img file to $osdir/tmp ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG

	if [ ! -f "$osdir"/tmp/"${osname}"*.img ] ; then	
        tar -xjpf "$osdir"/"$osfile" -C "$osdir"/tmp/   2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	fi
        if [ -f "$osdir"/tmp/"${osname}"*.img ] ; then
           #
           mkdir "$osdir"/"$osname"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;

           echo "mounting img file ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
           if echo "$osname" | grep "bsd" >/dev/null ; then 
	   # use dd insteed of mount 
	   # mount -t ufs -o loop,rw,ufstype=44bsd "$osdir"/tmp/"$osname"".img" "$osdir"/"$osname" 
           echo "" >/dev/null ; 
	   else 
           mount -o loop,ro "$osdir"/tmp/"$osname"".img" "$osdir"/"$osname"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
           fi ; 
        else
           cp -dpRxf "$osdir"/tmp/. "$osdir"/"$osname"/  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        fi 

    # create xen domus lvm partition
    echo "creating xen partition"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        sleep 4
        lvcreate -L "$disksize" -n "$vmname"_img $VG  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        if echo "$osname" | grep "bsd" >/dev/null ; then
                /sbin/mkfs.ufs -m 1 -O 1 -b 16384 -f 2048 /dev/$VG/"$vmname"_img  >/dev/null 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
                # /sbin/mkufs -O 1 -b 16384 -f 2048 /dev/$VG/"$vmname"_img ; 
        else 
            	mkfs -t ext3 /dev/$VG/"$vmname"_img  >/dev/null 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        fi 
	mkdir /mnt/"$vmname"_img  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG; 
    echo "creating swap ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
    sleep 4
    lvcreate -L "$swapsize" -n "$vmname"_swap $VG  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
    mkswap /dev/$VG/"$vmname"_swap  >/dev/null 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;

    # mounting partition and copying contents
        sleep 4
    if echo "$osname" | grep "bsd" >/dev/null ; then
        echo "duplicating contents to /mnt/${vmname}_img ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        dd if="$osdir"/tmp/"$osname"".img" of=/dev/$VG/"$vmname"_img bs=1M count=1000000  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        echo "running fsck before mounting..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        fsck -y -t ufs /dev/$VG/"$vmname"_img  >/dev/null 2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;

        echo "mounting /dev/$VG/${vmname}_img on /mnt/${vmname}_img ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	if echo $osname |grep "netbsd" >/dev/null ; then
        mount -t ufs -o loop,rw,ufstype=44bsd /dev/$VG/"$vmname"_img /mnt/"$vmname"_img  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	elif echo $osname |grep "freebsd" >/dev/null ; then
        mount -t ufs -o loop,rw,offset=$((63*512)),ufstype=44bsd /dev/$VG/"$vmname"_img /mnt/"$vmname"_img  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
	fi
    else
        echo "mounting /dev/$VG/${vmname}_img on /mnt/${vmname}_img ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        mount /dev/$VG/"$vmname"_img /mnt/"$vmname"_img  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        echo "duplicating contents to /mnt/${vmname}_img ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
        cp -dpRxf "$osdir"/"$osname"/. /mnt/"$vmname"_img/  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG;
    fi ;

    ###########################################################
    # edit system network files
    ###########################################################

	
    if [ "$ipone" == "" ] ; then
    echo "type first dedicated ip :"
        read ipone
    echo "Second dedicated ip or leave empty :"
        read iptwo
    fi

    #local hname="$vmname"".emohost.net"
    local hname=localhost.localdomain
    local gwaddr=${mainips_array[0]}
    local netmask=${netmask}
 
    if [ -f /mnt/"$vmname"_img/boot/grub/menu.lst ]; then
        local bootfile="/mnt/${vmname}_img/boot/grub/menu.lst"
    elif [ -f /mnt/"$vmname"_img/boot/grub/grub.conf ]; then
        local bootfile="/mnt/${vmname}_img/boot/grub/grub.conf"
    fi ;

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # RHEL OSES
    if echo "$osname" | grep "centos\|fedora\|cloudLinux\|mandriva\|scientific"  >/dev/null ; then
    echo "disabling selinux ..." 
    echo -e "SELINUX=disabled \n SELINUXTYPE=targeted" > /mnt/"$vmname"_img/etc/selinux/config ;
        sleep 2 ;
        rm -rf /mnt/"$vmname"_img/etc/hosts ;
    echo "creating /ect/hosts file..." 
        sleep 2 ;
        touch /mnt/"$vmname"_img/etc/hosts ;
        echo "127.0.0.1 localhost.localdomain localhost" > /mnt/"$vmname"_img/etc/hosts ;
        echo "$ipone" "$hname" "$vmname" >> /mnt/"$vmname"_img/etc/hosts ;
    echo "copying resolv.conf..." ;
        sleep 2
        rm -rf /mnt/"$vmname"_img/etc/resolv.conf 2>/dev/null ;
        cp -rf /etc/resolv.conf /mnt/"$vmname"_img/etc/resolv.conf ;
        echo "nameserver 8.8.8.8" >> /mnt/"$vmname"_img/etc/resolv.conf ;
    echo "editing /etc/sysconfig/network..."  
        sleep 2
        echo "NETWORKING=yes" > /mnt/"$vmname"_img/etc/sysconfig/network;
        echo 'HOSTNAME="'"$hname"'"' >> /mnt/"$vmname"_img/etc/sysconfig/network;
        echo "GATEWAY=""$gwaddr" >> /mnt/"$vmname"_img/etc/sysconfig/network;
    echo "editing ifcfg-eth0...and ifcfg-eth0:0"
        sleep 2
        echo -e "DEVICE=eth0
                BOOTPROTO=static
                ONBOOT=yes
                TYPE=Ethernet
                IPADDR=$ipone
               	HWADDR=$macaddr
                GATEWAY=$gwaddr
                NETMASK=$netmask
                SCOPE='peer $gwaddr'
                PEERDNS=NO " > /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0 ;
        sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0 ;
        if [ "$iptwo" != "" ] ; then
        touch /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0:0 ;
        echo -e "DEVICE=eth0:0
                BOOTPROTO=static
                ONBOOT=yes
                TYPE=Ethernet
                IPADDR=$iptwo
                NETMASK=$netmask
                PEERDNS=NO " > /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0:0 ;
        sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0:0 ;
        fi 
    echo "editing route-eth0..."
        sleep 2
        echo -e "ADDRESS0=$ipone
                NETMASK0=$netmask
                GATEWAY0=$gwaddr " > /mnt/"$vmname"_img/etc/sysconfig/network-scripts/route-eth0 ;
        sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/sysconfig/network-scripts/route-eth0 ;

        # CENTOS 6 - MANDRIVA 2010 2011
        #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if echo "$osname" | grep "centos.6\|mandriva\|scientific"  >/dev/null ; then
        echo "editing ifcfg-eth0...and ifcfg-eth0:0"
        sleep 2
        echo -e "DEVICE=eth0
                BOOTPROTO=static
                NM_CONTROLLED=\"no\"
                ONBOOT=yes
                TYPE=Ethernet
                IPADDR=$ipone
               	HWADDR=$macaddr
                GATEWAY=$gwaddr
                NETMASK=$netmask
                SCOPE='peer $gwaddr'
                PEERDNS=NO " > /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0 ;
        sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0 ;
	fi
        if [ "$iptwo" != "" ] ; then
        touch /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0:0 ;
        echo -e "DEVICE=eth0:0
                BOOTPROTO=static
                ONBOOT=yes
                TYPE=Ethernet
                IPADDR=\"$iptwo\"
                NETMASK=\"$netmask\"
                PEERDNS=NO " > /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0:0 ;
        sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/sysconfig/network-scripts/ifcfg-eth0:0 ;
        echo "editing route-eth0..."
        sleep 2
        echo -e "ADDRESS0=$ipone
                NETMASK0=$netmask
                GATEWAY0=$gwaddr " > /mnt/"$vmname"_img/etc/sysconfig/network-scripts/route-eth0 ;
        sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/sysconfig/network-scripts/route-eth0 ;
        fi 
        # MANDRIVA 2010 2011
        #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if echo "$osname" | grep "mandriva" >/dev/null ; then
            if ! cat /mnt/"$vmname"_img/etc/hostname | grep "$hname"  >/dev/null ; then
            echo "$hname" > /mnt/"$vmname"_img/etc/hostname ;
            fi ;
            if ! cat /mnt/"$vmname"_img/etc/rc.local | grep "bin/hostname"  >/dev/null ; then
            # To have the system set the correct hostname on startup
            echo "/bin/hostname -F /etc/hostname" >> /mnt/"$vmname"_img/etc/rc.local ;
            fi 
        fi 
    fi    

    if echo "$osname" | grep "netbsd\|freebsd"  >/dev/null ; then
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # NETBSD 5.02 - 5.1
    # http://www.gentoo-wiki.info/HOWTO_IP_Aliasing
    # http://www.netbsd.org/docs/guide/en/chap-net-practice.html
    # http://www.ifrankie.com/?p=148

        # kernel requirements
	if echo	"$osname" |grep	-i "netbsd" >/dev/null; then
                if echo "$osname" |grep "x86-64" >/dev/null; then
                        echo "copying netbsd kernel file ..."
                       	sleep 2
			if [ ! -f netbsd."$netbsdv".XEN3_DOMU ] ; then
                	chmod u=rwx,g=rx,o=rx "$osdir"/tmp/netbsd."$netbsdv".XEN3_DOMU ;
                	cp -rf "$osdir"/tmp/netbsd."$netbsdv".XEN3_DOMU /boot/ ;
			fi
		else
                        chmod u=rwx,g=rx,o=rx "$osdir"/tmp/netbsd."$netbsdv".XEN3PAE_DOMU ;
                        cp -rf "$osdir"/tmp/netbsd."$netbsdv".XEN3PAE_DOMU /boot/ ;
		fi
        fi

        if echo "$osname" |grep -i "freebsd" >/dev/null; then
                if echo "$osname" |grep "x86-64" >/dev/null; then
                        echo "copying freebsd kernel file ..."
                        sleep 2
                        if [ ! -f freebsd."$freebsdv".XEN3_DOMU ] ; then
                        chmod u=rwx,g=rx,o=rx "$osdir"/tmp/freebsd."$freebsdv".XEN3_DOMU ;
                        cp -rf "$osdir"/tmp/freebsd."$freebsdv".XEN3_DOMU /boot/ ;
                        fi
                else
                    	chmod u=rwx,g=rx,o=rx "$osdir"/tmp/freebsd."$freebsdv".XEN3PAE_DOMU ;
                        cp -rf "$osdir"/tmp/freebsd."$freebsdv".XEN3PAE_DOMU /boot/ ;
                fi
        fi

            sleep 2
        echo "copying resolv.conf..." ;
            rm -rf /mnt/"$vmname"_img/etc/resolv.conf 2>/dev/null ;
            # cp -rf /etc/resolv.conf /mnt/"$vmname"_img/etc/resolv.conf ;
            echo "nameserver 8.8.8.8" > /mnt/"$vmname"_img/etc/resolv.conf ;
            echo "nameserver 8.8.4.4" >> /mnt/"$vmname"_img/etc/resolv.conf ;

            sleep 2
        echo "configuring network interface(s) ..."
        if echo "$osname" | grep "freebsd" >/dev/null ; then

	    #if [ -f /mnt/"$vmname"_img/etc/rc.d/ccd  ] ; then
		#if ! cat /mnt/"$vmname"_img/etc/rc.d/ccd | grep "/etc/rs" >/dev/null ; then
		#sed -e 's/ccd_start().*/ \
		#\/etc\/rs \
		#ccd_start() \
		#/g' /mnt/"$vmname"_img/etc/rc.d/ccd ;
		#fi
		#sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/rc.d/ccd ;
	    #fi


            sed -i 's/ifconfig_.*//g' /mnt/"$vmname"_img/etc/rc.conf ;
            sed -i 's/defaultrouter_.*//g' /mnt/"$vmname"_img/etc/rc.conf ;

            echo -e "
                    hostname=\"$hname\"
                    # xn0 iface
                    ifconfig_xn0=\"inet $ipone netmask $netmask\"
                    " >> /mnt/"$vmname"_img/etc/rc.conf ;

            if [ "$iptwo" != "" ] ; then
            echo -e "
                    ifconfig_xn0_alias0=\"$iptwo netmask $netmask\"
                    " >> /mnt/"$vmname"_img/etc/rc.conf ;
            fi ;

                sleep 2
            echo "configuring gateway ..."
            echo -e "
                    # Default gateway
                    defaultrouter=\"$gwaddr\"
                    " >> /mnt/"$vmname"_img/etc/rc.conf ;

                sleep 2
            echo "enabling fsck..."
                #sed -i 's/fsck_y_enable=.*/fsck_y_enable="NO"/g' /mnt/"$vmname"_img/etc/rc.conf ;
            echo "adding growfs entries at startup..."
	            if ! cat /mnt/"$vmname"_img/etc/rc.conf | grep "growfs_y_enable" >/dev/null ; then
        	    echo 'growfs_y_enable="YES"' >> /mnt/"$vmname"_img/etc/rc.conf ;
            	    fi

              	sleep 2
            echo "adding xe_guest_update script entry to crontab..."
            if cat /mnt/"$vmname"_img/etc/crontab | grep "xe-update-bsdguest-stats" >/dev/null ; then
            echo "@reboot  root  /usr/sbin/xe-update-bsdguest-stats" >> /mnt/"$vmname"_img/etc/crontab ;
            fi

        elif echo "$osname" | grep "netbsd" >/dev/null ; then

                if [ ! -f /mnt/"$vmname"_img/etc/rs ] ; then
                echo "custom files not found. Abording..."
                elif [ ! -f /mnt/"$vmname"_img/etc/swaptool ] ; then
                echo "custom files not found. Abording..."
                elif [ ! -f /mnt/"$vmname"_img/usr/pkg/sbin/xe-update-netbsdguest-stats ] ; then
                echo "custom files not found. Abording..."
                fi

                sleep 2
            echo "setting up network..."
            sed -i 's/hostname=.*/hostname=netbsd/g' /mnt/"$vmname"_img/etc/rc.conf ;

            if cat /mnt/"$vmname"_img/etc/rc.conf |grep "ifconfig_xennet0" >/dev/null ; then
                sed -i 's/ifconfig_xennet0=.*/ifconfig_xennet0="inet '$ipone' netmask '$netmask'"/g' /mnt/"$vmname"_img/etc/rc.conf ;
                sed -i 's/ifconfig_xennet0_alias0=.*/ifconfig_xennet0_alias0="'$iptwo' netmask '$netmask'"/g' /mnt/"$vmname"_img/etc/rc.conf ;
            else
                echo "ifconfig_xennet0=\"inet $ipone netmask $netmask\" " >> /mnt/"$vmname"_img/etc/rc.conf ;
                if [ "$iptwo" != "" ] ; then
                echo "ifconfig_xennet0_alias0=\"$iptwo netmask $netmask\" " >> /mnt/"$vmname"_img/etc/rc.conf ;
                fi
            fi
              	sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/rc.conf ;
                sleep 2
            echo "configuring gateway ..."
            echo "$gwaddr" > /mnt/"$vmname"_img/etc/mygate ;

                sleep 2
            echo "configuring route ..."
            if ! cat /mnt/"$vmname"_img/etc/rc.conf | grep "defaultroute" >/dev/null ; then
            echo "defaultroute=$gwaddr" >> /mnt/"$vmname"_img/etc/rc.conf ;
            fi 

                #sleep 2
            #echo "adding growfs entries at startup ..."
            #if ! cat /mnt/"$vmname"_img/etc/rc.d/fsck | grep "growfs" >/dev/null ; then
            #sed -i 's/echo.*Starting file.*/ \
                #echo "Starting file system checks:" \
                #echo "growfs started..." \
                #\/usr\/pkg\/bin\/growfs -y \/dev\/rxbd0a ; \
                #fsck -y \/dev\/rxbd0a ; \
                #/g' /mnt/"$vmname"_img/etc/rc.d/fsck ;
            #fi ;
        fi 

            sleep 2
        echo "setting up hostname ..."
            if cat /mnt/"$vmname"_img/etc/rc.conf | grep "$hname" >/dev/null ; then
                sed -i 's/hostname=.*/hostname='$hname'/g' /mnt/"$vmname"_img/etc/rc.conf ;
            else
                echo "hostname=\"$hname\" " >> /mnt/"$vmname"_img/etc/rc.conf ;
            fi 

            if cat /mnt/"$vmname"_img/etc/rc.conf | grep "sshd=" >/dev/null ; then
                sed -i 's/sshd=.*/sshd=\"YES\"/g' /mnt/"$vmname"_img/etc/rc.conf ;
            else
                if echo "$osname" | grep "netbsd" >/dev/null ; then
                echo 'sshd="YES"' >> /mnt/"$vmname"_img/etc/rc.conf ;
                else
                echo 'sshd_enable="YES"' >> /mnt/"$vmname"_img/etc/rc.conf ;
                fi 
            fi 

            if ! cat /mnt/"$vmname"_img/etc/hosts | grep "$hname" >/dev/null ; then
            echo "$ipone $hname $vmname" > /mnt/"$vmname"_img/etc/hosts
            fi 

            sleep 2
        echo "disable dhcp on startup ..."
            if echo "$osname" | grep "freebsd"  >/dev/null ; then
                if ! cat /etc/rc.conf | grep "dhcpd_enable" >/dev/null ; then
                        echo 'dhcpd_enable="NO"' >> /etc/rc.conf ;
                else
                    	sed -i 's/dhcpd_enable=.*/dhcpd_enable="NO"/g' /etc/rc.conf ;
                fi 
            fi 
            if echo "$osname" | grep "netbsd"  >/dev/null ; then
                if ! cat /etc/rc.conf | grep "dhclient" >/dev/null ; then
                        echo 'dhclient="NO"' >> /etc/rc.conf ;
                else
                        sed -i 's/dhclient=.*/dhclient="NO"/g' /etc/rc.conf ;
                fi 
            fi 
    fi

    if echo "$osname" | grep "debian\|ubuntu"  >/dev/null ; then
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # DEBIAN 5 - 6

            sleep 1
        echo "copying resolv.conf..." ;
            rm -rf /mnt/"$vmname"_img/etc/resolv.conf 2>/dev/null ;
            cp -rf /etc/resolv.conf /mnt/"$vmname"_img/etc/resolv.conf ;
            echo "nameserver 8.8.8.8" >> /mnt/"$vmname"_img/etc/resolv.conf ;

            sleep 1
        echo "setting up hostname ..."
            if ! cat /mnt/"$vmname"_img/etc/hostname | grep "$hname" >/dev/null  ; then
            echo "$hname" > /mnt/"$vmname"_img/etc/hostname ;
            fi ;

        echo "creating /ect/hosts file..." ;
            sleep 1 ;
            echo "127.0.0.1 localhost.localdomain localhost" > /mnt/"$vmname"_img/etc/hosts ;
            echo "$ipone" "$hname" "$vmname" >> /mnt/"$vmname"_img/etc/hosts ;

            sleep 1
        echo "configuring network interfaces ..."
        echo "
              	auto eth0
                iface eth0 inet static
                address $ipone
                netmask $netmask
                broadcast $bdcast
                gateway $gwaddr
                pointopoint $gwaddr
                # up route add -net $ipone netmask $netmask gw $gwaddr
                # down route del -net $gwaddr netmask $netmask gw $gwaddr
        " > /mnt/"$vmname"_img/etc/network/interfaces ;

        if [ "$iptwo" != "" ] ; then
        echo "
              	# aliasing d'interface
                auto eth0:1
                iface eth0:1 inet static
                address $iptwo
                netmask $netmask
                broadcast $bdcast
        " >> /mnt/"$vmname"_img/etc/network/interfaces ;
        fi ;
	sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/network/interfaces ;

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # opt.
            sleep 1
        if [ ! -f /mnt/"$vmname"_img/etc/network/options ]; then
            echo "" > /mnt/"$vmname"_img/etc/network/options ;
        fi ;
	if ! cat /mnt/"$vmname"_img/etc/network/options | grep 'ip_forward' >/dev/null ; then
            echo "ip_forward=no" >> /mnt/"$vmname"_img/etc/network/options ;
        else
            sed -i 's/ip_forward=.*/ip_forward=no/g' /mnt/"$vmname"_img/etc/network/options ;
        fi ;
	if ! cat /mnt/"$vmname"_img/etc/network/options | grep 'spoofprotect' >/dev/null ; then
            echo "spoofprotect=yes" >> /mnt/"$vmname"_img/etc/network/options ;
        else
            sed -i 's/spoofprotect=.*/spoofprotect=yes/g' /mnt/"$vmname"_img/etc/network/options ;
        fi ;
	sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/network/options ;
    fi
     
    if echo "$osname" | grep "gentoo"  >/dev/null ; then
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # GENTOO
    # http://www.gentoo.org/doc/en/handbook/handbook-x86.xml?part=1&chap=8

            sleep 1
        echo "copying resolv.conf..." ;
            rm -rf /mnt/"$vmname"_img/etc/resolv.conf 2>/dev/null ;
            cp -rf /etc/resolv.conf /mnt/"$vmname"_img/etc/resolv.conf ;
            echo "nameserver 8.8.8.8" >> /mnt/"$vmname"_img/etc/resolv.conf ;

            sleep 1
        echo "setting up hostname ..."
            if ! cat /mnt/"$vmname"_img/etc/hostname | grep "$hname" >/dev/null ; then
            echo "$hname" > /mnt/"$vmname"_img/etc/hostname ;
            fi ;

        echo "creating /ect/hosts file..." ;
            sleep 1 ;
            echo "127.0.0.1 localhost.localdomain localhost" > /mnt/"$vmname"_img/etc/hosts ;
            echo "$ipone" "$hname" "$vmname" >> /mnt/"$vmname"_img/etc/hosts ;

        echo "configuring network eth0 ..."
            sleep 1
            echo "
            config_eth0='$ipone netmask $netmask brd $bdcast'
            gateway='eth0/$gwaddr'
            routes_eth0=( 'default via $gwaddr' )
            mac_eth0='$macaddr'
            " >/mnt/"$vmname"_img/etc/conf.d/net ;

        if [ "$iptwo" != "" ] ; then
            echo "
            # alias_eth0=('192.168.0.2', '192.168.0.3')
            alias_eth0=('$iptwo')
            # broadcast_eth0=('192.168.0.255', '192.168.0.255')
            broadcast_eth0=('$bdcast')
            # netmask_eth0=('255.255.255.0', '255.255.255.0')
            netmask_eth0=('$netmask')
            " >>/mnt/"$vmname"_img/etc/conf.d/net ;
        fi ;
            sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/conf.d/net ;
    fi

    if echo "$osname" | grep "opensolaris\|solaris" >/dev/null ; then
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Solaris
    # http://www.gentoo.org/doc/en/handbook/handbook-x86.xml?part=1&chap=8
    # http://cyruslab.wordpress.com/2012/02/09/arch-linux-install-yaourt/
    # https://aur.archlinux.org/packages/xe-guest-utilities/?setlang=fr
        echo ""
    fi ;

    if echo "$osname" | grep "opensuse"  >/dev/null ; then
    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # OPENSUSE
    # http://www.softpanorama.org/Net/Linux_networking/Suse_networking/index.shtml
    # http://www.susegeek.com/networking/how-to-setup-persistent-static-routes-in-opensuse-110/

            sleep 1
        echo "copying resolv.conf..." ;
            rm -rf /mnt/"$vmname"_img/etc/resolv.conf 2>/dev/null ;
            cp -rf /etc/resolv.conf /mnt/"$vmname"_img/etc/resolv.conf ;
            echo "nameserver 8.8.8.8" >> /mnt/"$vmname"_img/etc/resolv.conf ;

            sleep 1
        echo "setting up hostname ..."
            if ! cat /mnt/"$vmname"_img/etc/hostname | grep "$hname" >/dev/null ; then
            echo "$hname" > /mnt/"$vmname"_img/etc/hostname ;
            fi ;

        echo "creating /ect/hosts file..." ;
            sleep 1 ;
            echo "127.0.0.1 localhost.localdomain localhost" > /mnt/"$vmname"_img/etc/hosts ;
            echo "$ipone" "$hname" "$vmname" >> /mnt/"$vmname"_img/etc/hosts ;

        # try to disable
        # .NETWORKMANAGER=.yes.. in /etc/sysconfig/network/config
       	# sed -i 's/NETWORKMANAGER=.*/NETWORKMANAGER=no/g' /mnt/"$vmname"_img/etc/sysconfig/network/config ;
            sleep 1
        echo "configuring network ..."
            echo "
            BOOTPROTO='static'
            IPADDR='$ipone'
            NAME=''
            NETMASK='$netmask'
            STARTMODE='auto'
            USERCONTROL='no'
            #IPADDR1='$ipone'
            #LABEL1='1'
            #IPADDR2='172.31.0.220/23'
            #LABEL2='2'
            " > /mnt/"$vmname"_img/etc/sysconfig/network/ifcfg-eth0 ;

            sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/sysconfig/network/ifcfg-eth0 ;
            sleep 1
        echo "default $gwaddr" > /mnt/"$vmname"_img/etc/sysconfig/network/routes ;
    fi
	

    ############################################################
    # global edit
    # fstab edit

        echo "setting up swap..."
        if echo $osname | grep "centos\|fedora\|cloudLinux\|cloudlinux\|mandriva\|scientific\|debian\|ubuntu\|opensuse\|slackware\|arch\|archlinux\|gentoo" >/dev/null ;
        then
            	echo "checking swap fstab..."
                if ! cat /mnt/"$vmname"_img/etc/fstab | grep "xvda2\|swap" >/dev/null ; then
                echo "/dev/xvda2        none    swap    sw 0 0" >> /mnt/"$vmname"_img/etc/fstab ;
                else
                sed -i 's/^\/dev\/xvda2.*/\/dev\/xvda2        none    swap    sw 0 0/g' /mnt/"$vmname"_img/etc/fstab ;
                fi
        fi

	if echo $osname | grep "netbsd" >/dev/null ; then
                sed -i 's/*.swap.*//g' /mnt/"$vmname"_img/etc/fstab ;
                echo "/dev/xbd1a  none  swap  sw  0 0" >>/mnt/"$vmname"_img/etc/fstab ;
        fi
	
	# replaced by /etc/swaptool
        if echo $osname | grep "freebsd" >/dev/null ; then
                sed -i 's/*.swap.*//g' /mnt/"$vmname"_img/etc/fstab ;
                #echo "/dev/xbd1   none   swap   sw   0 0" >> /mnt/"$vmname"_img/etc/fstab ;
        fi

	if echo $osname | grep "solaris" >/dev/null ; then
                # search for disk # https://blogs.oracle.com/observatory/entry/which_disk_devices_to_use
                # format disk # http://utahsysadmin.com/2008/04/10/how-to-add-a-swap-drive-to-solaris-10/
                sed -i 's/*.swap.*//g' /mnt/"$vmname"_img/etc/vfstab ;
                echo "/dev/dsk/c7d1p0   -   -   swap   -   no   - " >>/mnt/"$vmname"_img/etc/vfstab ;
        fi

	echo "global resolv edit..."
            sleep 1
        echo -e "
        ################################
        # emohost.com - imageinstaller #
        # nameserver config
        nameserver 8.8.8.8
        nameserver 8.8.4.4
        " > /mnt/"$vmname"_img/etc/resolv.conf ;
        sed -i 's/^[ \t]*//'  /mnt/"$vmname"_img/etc/resolv.conf ;

        # echo "updating /boot/grub/menu.lst file ..."
        #    sleep 1
        # sed -i 's/timeout=.*/timeout=5/g' "$bootfile" ;
        # sed -i 's/root=\/dev\/xvd.*/root=\/dev\/xvda1 ro/g' "$bootfile" ;
	
	# LINUX
        newpasswd=$2
        hashedpasswd=$(perl -e "print crypt('"$newpasswd"','\$6\$2869xJ1s\$')")
        endofile=$(grep "^root" /mnt/"$vmname"_img/etc/shadow 2>/dev/null | grep -o ":[0-9].*")
        password=root:${hashedpasswd}${endofile}
	#
        echo "setting up new password..." 
        if echo $osname | grep "archlinux\|centos\|fedora\|cloudlinux\|gentoo\|scientific\|debian\|ubuntu\|opensuse\|slackware" >/dev/null ;
        then
            	echo "setting root password..."
                if [ -f /mnt/"$vmname"_img/etc/shadow ] ; then
                sed -i 's|^root:.*|'$password'|g' /mnt/"$vmname"_img/etc/shadow ;
		# echo ""
                fi
        fi


	# UNIX
        newpasswd=$2
        echo "setting up new password..."
        if echo $osname | grep "freebsd\|netbsd" >/dev/null ;
        then
		echo $newpasswd > /mnt/"$vmname"_img/password ;		
                #echo "setting root password..."
                #if [ -f /mnt/"$vmname"_img/etc/master.passwd ] ; then
		#	hashedpasswd=$(perl -e "print crypt('"$newpasswd"','\$1\$2869xJ1s\$')")
		#	endofile=$(grep "^root" /mnt/"$vmname"_img/etc/master.passwd 2>/dev/null |grep -o ":[0-9].*" |sed 's|&|\\&|g')
		#	password=root:${hashedpasswd}${endofile}
		#	sed -i "s|^root.*|$password|g" /mnt/"$vmname"_img/etc/master.passwd ;
                #fi
        fi


    ############################################################
    # create xen domain conf file
    ############################################################
    local vmram=$( echo $totalram | sed 's/MB//g' | sed 's/M//g')

    #if [ ! -f /etc/xen/"$vmname".cfg ] ; then
        echo "
	bootloader = '/usr/bin/pygrub'
        name = '"$vmname"'
        vcpus = $ncores
        memory = $vmram
        extra = 'console=hvc0 xencons=tty'
        root = '/dev/xvda1'
        disk = [
        'phy:/dev/"$VG"/"$vmname"_img,xvda1,w',
        'phy:/dev/"$VG"/"$vmname"_swap,xvda2,w',
        ]
	vif = [ 'ip=$ipone $iptwo,mac=$macaddr' ]
        on_poweroff = 'destroy'
        on_reboot = 'restart'
        on_crash = 'restart'
        extra = 'fastboot'
        " > /etc/xen/"$vmname".cfg ;

        # global freebsd .cfg creation condition
        if echo $osname | grep "freebsd" >/dev/null ; then

                dev_model=$(find /usr/lib* -name "qemu-dm" | head -1)
                hvm_loader=$(find /usr/lib* -name "hvmloader" | head -1)

                # version condition

                if echo $osname | grep "8.0" >/dev/null ;
                # PV only
                then
                echo  -e "
                        #  -*- mode: python; -*-
                        kernel = '/boot/freebsd.${freebsdv}.XEN3PAE_DOMU'
                        vcpus = $ncores
                        memory = $vmram
                        name = '"$vmname"'
                        disk = [
                        'phy:/dev/"$VG"/"$vmname"_img,0xCA00,w',
                        'phy:/dev/"$VG"/"$vmname"_swap,0xCA10,w',
                        ]
                        vif = [ 'ip=$ipone $iptwo,mac=$macaddr' ]
                        extra = 'console=hvc0 xencons=tty'
                        extra += ',boot_verbose=1'
                        #extra += ',boot_single=1'
                        #extra += ',vfs.root.mountfrom=ufs:/dev/xbd0s1'
                        extra += ',vfs.root.mountfrom=ufs:/dev/xbd0'
                        extra += ',kern.hz=100'
                        on_poweroff = 'destroy'
                        on_reboot = 'restart'
                        on_restart = 'restart'
                        on_crash = 'restart'
                        " > /etc/xen/"$vmname".cfg ;
                fi

                if echo $osname | grep "[8-9]-[0-9]" >/dev/null ;
                then
                # HVM only
                echo -e "
                        bootloader = '$hvm_loader'
                        builder='hvm'
                        memory = '$vmram'
                        vcpus = $ncores
                        device_model = '$dev_model'
                        name = '"$vmname"'
                        vif = [ 'ip=$ipone $iptwo,mac=$macaddr' ]
                        disk = [
                        'phy:/dev/"$VG"/"$vmname"_img,hda,w',
                        'phy:/dev/"$VG"/"$vmname"_swap,hdb,w',
                        ]
                        boot = 'c'
                        vfb = [ 'type=vnc,vncdisplay="$vmid",vncpasswd=' ]
                        vnc = 0
                        vncconsole=0
                        vncpasswd=''
                        serial='pty'
                        sdl = 0
                        apic = 1
                        acpi = 1
                        usb = 0
                        localtime = 0
                        pae = 1
                        stdvga = 0
                        videoram = 4
                        shadow_memory = 4
                        timer_mode = 1
                        on_poweroff = 'destroy'
                        on_reboot = 'restart'
                        on_restart = 'restart'
                        on_crash = 'restart'
                        " > /etc/xen/"$vmname".cfg ;
                fi
                sed -i 's/^[ \t]*//'  /etc/xen/"$vmname".cfg ;
        fi

        if echo "$osname" | grep "netbsd" >/dev/null ; then
            # check if i386 or amd64
            # i386
            if echo $osname | grep "x86" >/dev/null ; then
            echo "
                kernel = '/boot/netbsd."$netbsdv".XEN3PAE_DOMU'
                name = '"$vmname"'
                vcpus = $ncores
                memory = $vmram
                extra = 'console=hvc0 xencons=tty'
                disk = [ 'phy:/dev/"$VG"/"$vmname"_img,sda1,w',
                'phy:/dev/"$VG"/"$vmname"_swap,sda2,w', ]
                root = 'xbd0a'
                vif = [ 'ip=$ipone $iptwo,mac=$macaddr' ]
                on_poweroff = 'destroy'
                on_reboot = 'restart'
                on_crash = 'restart'
                extra = 'fastboot'
                " > /etc/xen/"$vmname".cfg ;
            fi

            if  echo $osname | grep "x86-64" >/dev/null ; then
            # amd64
            echo "
                kernel = '/boot/netbsd."$netbsdv".XEN3_DOMU'
                name = '"$vmname"'
                vcpus = $ncores
                memory = $vmram
                extra = 'console=hvc0 xencons=tty'
                disk = [ 'phy:/dev/"$VG"/"$vmname"_img,sda1,w',
                'phy:/dev/"$VG"/"$vmname"_swap,sda2,w', ]
                root = 'xbd0a'
                vif = [ 'ip=$ipone $iptwo,mac=$macaddr' ]
                on_poweroff = 'destroy'
                on_reboot = 'restart'
                on_crash = 'restart'
                extra = 'fastboot'
                " > /etc/xen/"$vmname".cfg ;
            fi
	fi

	if echo $osname | grep "opensolaris" >/dev/null ; then
        echo "
              	bootloader = '/usr/bin/pygrub'
                name = '"$vmname"'
                vcpus = $ncores
                memory = $vmram
                disk = [ 'phy:/dev/"$VG"/"$vmname"_img,0,w',
                'phy:/dev/"$VG"/"$vmname"_swap,1,w' ]
                vif = [ 'ip=$ipone $iptwo,mac=$macaddr' ]
                on_shutdown = 'destroy'
                on_reboot = 'destroy'
                on_crash = 'destroy'
                extra = 'console=hvc0 xencons=tty'
                extra = 'boot_verbose=1
                " > /etc/xen/"$vmname".cfg ;
        fi

        # clean whitespace
        sed -i 's/^[ \t]*//'  /etc/xen/"$vmname".cfg ;
    #fi ;


    echo "updating xen_lists.txt file ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG
    sleep 3
    # emohost 188.40.110.88

    if ! cat /xen_lists.txt | grep "${vmname} " >/dev/null ; then 
    	echo "$vmname" "$ipone" >> /xen_lists.txt ;
    else
    	sed -i 's/^.*'$vmname' .*//g' /xen_lists.txt ;
        echo "$vmname" "$ipone" >> /xen_lists.txt ;
    fi

    echo "unmounting mount folders ..."  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG
    sleep 1
    umount -f "$osdir"/"$osname"  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG ;
    umount -f /mnt/"$vmname"_img   2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG ;

    # echo "disable network manager by running 'chkconfig NetworkManager off' ..."
    echo "done."

    xm create ${vmname}.cfg  2>&1 |eval 'log=$(cat);echo $TIME $log' |tee -a $LOG ;
	
    exit 
}

#####################################################
# Choice
#####################################################

  if [ "$option" == "" ] ; then
  echo "A] witch vm to setup [ type a , b , or c ... ]"
  echo "
  a) xs vps
  b) s vps
  c) m vps
  d) l vps
  e) custom vps "
  read option
  fi 

  if [ "$option" == "a" ]; then
  ncores="1"
  disksize="30GB"
  totalram="512MB"
  swapsize="1024MB"

  elif [ "$option" == "b" ]; then
  ncores="2"
  disksize="30GB"
  totalram="512MB"
  swapsize="1024MB"

  elif [ "$option" == "c" ]; then
  ncores="3"
  disksize="50GB"
  totalram="1024MB"
  swapsize="2048MB"

  elif [ "$option" == "d" ]; then
  ncores="4"
  disksize="70GB"
  totalram="2048MB"
  swapsize="4096MB"

  elif [ "$option" == "custom" ]; then
  ncores="$6"
  totalram="$7""MB"
  disksize="$8""GB"
  swapsize="$9""GB"

  elif [ "$option" == "e" ]; then
    function custom_vps(){
    echo "Enter n value for cpu cores (max cores: 4) : " ; read ncores
    echo "Enter n value for disk size (without GB) : " ; read disksize
    echo "Enter n value for total ram amount (without MB) : " ; read totalram
    echo "Enter n swap size (without MB) : " ; read swapsize
    disksize="$disksize""GB"
    totalram="$totalram""MB"
    swapsize="$swapsize""MB"
    echo "Printing variables ..."
    echo -e "ncores=$ncores \n""disksize=$disksize \n""totalram=$totalram \n""swapsize=$swapsize \n"
    echo "Continue? [yY/nN] " ; read ans
    if [[ "$ans" -ne "y" || "$ans" -ne "Y" ]]; then custom_vps ; fi ;
    }
    custom_vps ;
  else echo "invalid choice." ;
       exit 1
  fi ;

# check if $4 arg is not empty
if [ "$oschoice" != "" ] ; then
	for i in ${!oseslist[@]};
	do 
		if 
		echo ${oseslist[$i]} | grep "$oschoice" >/dev/null ; then 
		osnum=$i
		break 
		fi 
	done
else
	echo "B] select the operating system for xen domu to install : "
	for i in ${!oseslist[@]};
	do 
		echo "$i) ${oseslist[$i]}"
	done ;
	echo "" ;
	read osnum
fi 
case $osnum in
    0)inst "0" "$newpasswd" ;;
    1)inst "1" "$newpasswd" ;;
    2)inst "2" "$newpasswd" ;;
    3)inst "3" "$newpasswd" ;;
    4)inst "4" "$newpasswd" ;;
    5)inst "5" "$newpasswd" ;;
    6)inst "6" "$newpasswd" ;;
    7)inst "7" "$newpasswd" ;;
    8)inst "8" "$newpasswd" ;;
    9)inst "9" "$newpasswd" ;;
    10)inst "10" "$newpasswd" ;;
    11)inst "11" "$newpasswd" ;;
    12)inst "12" "$newpasswd" ;;
    13)inst "13" "$newpasswd" ;;
    14)inst "14" "$newpasswd" ;;
    15)inst "15" "$newpasswd" ;;
    16)inst "16" "$newpasswd" ;;
    17)inst "17" "$newpasswd" ;;
    18)inst "18" "$newpasswd" ;;
    19)inst "19" "$newpasswd" ;;
    20)inst "20" "$newpasswd" ;;
    21)inst "21" "$newpasswd" ;;
    22)inst "22" "$newpasswd" ;;
    23)inst "23" "$newpasswd" ;;
    24)inst "24" "$newpasswd" ;;
    25)inst "25" "$newpasswd" ;;
    26)inst "26" "$newpasswd" ;;
    27)inst "27" "$newpasswd" ;;
    28)inst "28" "$newpasswd" ;;
    29)inst "29" "$newpasswd" ;;
    30)inst "30" "$newpasswd" ;;
    31)inst "31" "$newpasswd" ;;
    32)inst "32" "$newpasswd" ;;
    33)inst "33" "$newpasswd" ;;
    34)inst "34" "$newpasswd" ;;
    35)inst "35" "$newpasswd" ;;
    36)inst "36" "$newpasswd" ;;
    37)inst "37" "$newpasswd" ;;
    38)inst "38" "$newpasswd" ;;
    39)inst "39" "$newpasswd" ;;
    40)inst "40" "$newpasswd" ;;
    41)inst "41" "$newpasswd" ;;
    42)inst "42" "$newpasswd" ;;
    43)inst "43" "$newpasswd" ;;
    44)inst "44" "$newpasswd" ;;
    45)inst "45" "$newpasswd" ;;
    46)inst "46" "$newpasswd" ;;
    47)inst "47" "$newpasswd" ;;
    48)inst "48" "$newpasswd" ;;
    49)inst "49" "$newpasswd" ;;
    50)inst "50" "$newpasswd" ;;
    *) echo "invalid choice" ;;
esac

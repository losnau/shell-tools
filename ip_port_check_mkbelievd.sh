#!/bin/bash

#---------------------------
#author：losnau
#create date：2018.01.12
#change date 01：2018.03.10
#脚本功能：检查一个某一个网段的IP地址是否可用，22端口是否到达，还可以批量建立信任关系
#使用方式：./shell.sh 172.16 5
#脚本运行身份：root
#注意事项：
#1.默认不建立信任关系，如果需要在main函数开启
#2.运行之前确保watson用户是否存在，密码是否正确，yum源是否OK
#----------------

network=$1
segment=$2
#watson_passwd=Watson${segment}@2017
watson_passwd=watson@123
yum_repo='ftp://192.168.20.25/rhe65.repo'
Home='/home/watson'
#-----------------------------
#环境初始化
#------------------------------
function init()
{
	#检查yum源，这里的检查yum仅仅适用于测试环境
 	sudo yum clean all   > /dev/null 2>&1
        sudo yum repolist > /dev/null 2>&1
        num=`yum repolist 2>/dev/null |grep repolist |awk '{print $2}'`
        if [[ $num == '0' ]]
        then
                Echo_Red "YUM源没有配置好，下面自动配置yu m源"
                cd /tmp/
                wget $yum_repo > /dev/null 2>&1
                sudo bash -c "mv rhe65.repo /etc/yum.repos.d/" >/dev/null 2>&1
        fi
	#安装nc命令，如果没有
	nmap -sP 127.0.0.1  >/dev/null 2>&1
	if [ $? -eq 127 ]
	then
		yum install nmap -y 
	fi
	#安装nmap命令，如果没有
	nc -z -w 1 127.0.0.1 22  >/dev/null 2>&1
	if [ $? -eq 127 ]
	then
		yum install nc -y 2>&1 
	fi
	if [ ! -d $Home/.ssh ]
	then
	#如果密钥不存在则,自动生成密钥
		su - watson -c  'ssh-keygen -t rsa -P "" -f ~/.ssh/id_rsa &>/dev/null'
	fi
	#安装expect命令，如果没有
	expect -h  >/dev/null 2>&1
	if [ $? -eq 127 ]
	then
		yum install expect -y 
	fi
	#判断检查的网段路径是否存在
	if [ ! -d $network.$segment ]
	then
		mkdir $network.$segment
	else
		echo $network.$segment'目录已存在，请转移或者删掉目录之后在运行该脚本'
	fi
	now_pwd=$(pwd)
	
	#文件里面保存网段中所有可以ping的IP地址
	ip_all="$network.$segment/ip_all_$segment"                                       
	#文件里面保存nmap扫描的原始数据
	ip_list="$network.$segment/ip_list_$segment" 
	host_linux="$network.$segment/host_linux_$segment"
	host_others="$network.$segment/host_others_$segment"
	echo "#可能对方是Linux主机，但是由于防火墙等种种原因导致无法访问；也有可能对方没有开启22端口；也哟有可能对方是windows主机" > $host_others

}


############
#建立信任关系
#
############
function make_believe(){
	ttt=1
	while read ip
	do
			/usr/bin/expect <<-EOF
set time 60
spawn   ssh-copy-id -i $Home/.ssh/id_rsa.pub watson@$ip
expect {
"*]*" { send "exit" }
"*yes/no*"  { send "yes\r"; exp_continue }
"*assword:" { send "$watson_passwd\r" }
}
interact
expect eof
EOF
	if [ $? -eq 0 ]
	then
		#将对方服务器的指纹复制到watson用户中
		cat /root/.ssh/known_hosts |grep $ip >> $Home/.ssh/known_hosts
		echo $ip,建立了信任关系
	#	exit 1 
		let ttt++
		echo "-----------------------循环："$ttt"次数"
	else
		echo $ip-------复制密钥失败
	fi
	done < $host_linux
}
#--------------------------------------
#
#获取一个C类地址中可用的IP地址
#
#--------------------------------------
function get_ip(){
	temp_num=0	
	nmap -sP $network.$segment.0/24 |grep $network > $ip_all  2>/dev/null   #nmap简单快速扫描获取所有可以ping的地址
	#对获取得到的信息加工，得到单独的IP地址
	ip_num=`cat $ip_all|wc -l`
	for i in `seq 1 $ip_num`
	do
		lie_ip=`cat $ip_all |sed -n $i'p'`
		lie_nf=`echo $lie_ip |awk '{print NF}'`
		#去掉网关地址
		if [[ "$lie_ip" == "$network.$segment.253" ]]
		then
			continue
		fi
		#只有IP地址，无主机名的时候
		if [[ $lie_nf == 5 ]]
		then
				ip=`echo $lie_ip|awk '{print $5}'`
				if [[ "$ip" == "$network.$segment.253" ]]
				then
					continue
				fi
				let temp_num++
				ip_arry_all[$temp_num]=$ip
				echo $ip >> $ip_list
		#有主机名的时候
		elif [ $lie_nf -eq 6 ]
		then
				ip=`echo $lie_ip|awk -F"(" '{print $2}'|awk -F")" '{print $1}'`
				echo $ip >> $ip_list
				let temp_num++
				ip_arry_all[$temp_num]=$ip
		else
				echo "$lie_ip------------------Error!!!!!!!!"
		fi
	done
}
#--------------------------------------
#
#从可用地址中确认os系统，确定22端口是否可达
#
#--------------------------------------
function confirm_os(){
	temp_num=0
	for((i=1;i<=${#ip_arry_all[@]};i++))
	do
#		echo $i,${ip_arry_all[$i]}
		#检查目的主机22端口是否可达
		nc -z -w 1 ${ip_arry_all[$i]} 22 >/dev/null 2>&1
		if [ $? -eq 0 ]
		then
			let temp_num++
			echo "IP:  ${ip_arry_all[$i]} 22端口可达"
			ip_arry[$temp_num]=${ip_arry_all[$i]}
			echo ${ip_arry_all[$i]} >> $host_linux
		elif [  $lie_nf -eq 1 ]
		then
			echo ${ip_arry_all[$i]} >> $host_others
		fi
	done

}

function main(){
	init
	get_ip
	confirm_os
	#make_believe
	chown watson:watson $now_pwd/$network.$segment -R
}
##############################################################################
#
#  颜色处理
#
##############################################################################
function Color_Text()
{
  echo -e " \e[0;$2m$1\e[0m"
}
function Echo_Red()
{
  echo $(Color_Text "$1" "31")
}
function Echo_Green()
{
  echo $(Color_Text "$1" "32")
}
function Echo_Yellow()
{
  echo $(Color_Text "$1" "33")
}
function Echo_Blue()
{
  echo $(Color_Text "$1" "34")
}

main

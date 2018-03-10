#!/bin/bash

#---------------------------
#脚本功能：检查一个某一个网段的IP地址是否可用，22端口是否到达，还可以批量建立信任关系
#使用方式：./shell.sh network
#----------------
#安装nc命令，如果没有
network=$1
#yum install nc -y 2>&1 
#自动生成密钥
#ssh-keygen -t rsa -P "" -f ~/.ssh/id_rsa

watson_passwd=Watson${network}@2017
if [ ! -d $network ]
then
    mkdir $network
fi
#文件里面保存网段中所有可以ping的IP地址
ip_all="$network/ip_all_$network"                                       
#文件里面保存nmap扫描的原始数据
ip_list="$network/ip_list_$network" 
host_linux="$network/host_linux_$network"
host_others="$network/host_others_$network"
echo "#可能对方是Linux主机，但是由于防火墙等种种原因导致无法访问；也有可能对方没有开启22端口；也哟有可能对方是windows主机" > $host_others
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
spawn   ssh-copy-id -i /home/watson/.ssh/id_rsa.pub watson@$ip
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

		#讲对方服务器的指纹复制到watson用户中
		cat /root/.ssh/known_hosts |grep $ip >> /home/watson/.ssh/known_hosts
		echo $ip,建立了信任关系
	#	exit 1 
		let ttt++
		echo "-----------------------循环："$ttt"次数"
	else
		echo $ip-------复制密钥失败
	fi
	done <$host_linux
}
#--------------------------------------
#
#获取一个C类地址中可用的IP地址
#
#--------------------------------------
function get_ip(){
	temp_num=0	
	nmap -sP 172.16.$network.0/24 |grep 172 > $ip_all  2>/dev/null   #获取所有可以ping的地址
	#对获取得到的信息加工，得到单独的IP地址
	ip_num=`cat $ip_all|wc -l`
	for i in `seq 1 $ip_num`
	do
		lie_ip=`cat $ip_all |sed -n $i'p'`
		lie_nf=`echo $lie_ip |awk '{print NF}'`
		#去掉网关地址
		if [[ "$lie_ip" == "172.16.$network.253" ]]
		then
			continue
		fi
		#只有IP地址，无主机名的时候
		if [[ $lie_nf == 5 ]]
		then
				ip=`echo $lie_ip|awk '{print $5}'`
				if [[ "$ip" == "172.16.$network.253" ]]
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
		nc -z -w 1 ${ip_arry_all[$i]} 22 >/dev/null 2>&1
		if [ $? -eq 0 ]
		then
			let temp_num++
			echo "IP:  ${ip_arry_all[$i]} 22端口可达"
			ip_arry[$temp_num]=${ip_arry_all[$i]}
			echo ${ip_arry_all[$i]} >> $host_linux
		elif [  $lie_nf -eq 1 ]
		then
			#使用nmap工具检测对方22端口是否开启
			#nmap -p T:22 -PN  172.16.17.45 |grep close > /dev/null 2>&1
			#if [ $? -eq 0  ]
			#then
			#	let temp_num++
			#	ip_arry[$temp_num]=${ip_arry_all[$i]}
			#	echo ${ip_arry_all[$i]} >> $host_linux
			#elif [ $? -eq 1 ]
			#then
			#fi

#			echo ${ip_arry_all[$i]}
			echo ${ip_arry_all[$i]} >> $host_others
		fi
	done

}
function main(){
	get_ip
	confirm_os
	#make_believe
	chown watson:watson /home/watson/beleve -R
}
main

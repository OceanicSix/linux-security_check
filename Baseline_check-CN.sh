#!/bin/bash

#该脚本需要使用root用户执行

#----------管理员可根据需要设定以下参数------------

#系统日志文件路径搜索路径
web_log=("/var/log/nginx/access.log" "/var/log/apache2/access.log" "/var/log/httpd/access_log" "/var/lib/tomcat/logs/localhost_access_log")
ssh_log=("/var/log/auth.log" "/var/log/secure")

#危险端口
examined_port=(21 22 3306)


echo ---------------------------------- | $save_result 
echo "Linux security inspection V1.0" | $save_result 
echo "Author:Sean" | $save_result 
echo "Update Date:2023-7-5" | $save_result 
echo ---------------------------------- | $save_result 
echo  | $save_result 

#定义颜色
RED='\033[0;31m'
GE='\033[0;32m'
YEL='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'


if [ $(whoami) != "root" ];then
	echo -e "${RED}安全检查必须使用root账号,否则某些项无法检查."
	exit 1
fi

date=$(date +%Y%m%d-%H%M%S 2>>${check_file}/error.log)
ipadd=$(ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}'| sed /s"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"/g 2>>${check_file}/error.log)

#设置结果保存目录
check_file="${ipadd}_${date}"
mkdir $check_file


#定义常用指令
save_result="tee -a ${check_file}/check_ressult.txt"
errorlog="tee -a ${check_file}/error.log"


echo -e "${YEL}-------------0.系统信息收集----------------------"| $save_result | $errorlog
echo -e "${GE}主机名: \t" $(hostname -s 2>>${check_file}/error.log) | $save_result
echo -e "操作系统: \t" $(cat /etc/os-release | grep PRETTY_NAME | awk -F '"' '{print $2}' 2>>${check_file}/error.log) | $save_result
echo -e "内核版本: \t" $(uname -r 2>>${check_file}/error.log) | $save_result
echo -e "CPU架构: \t" $(cat /proc/cpuinfo | grep 'model name' | sort -u | awk -F ":" '{print $2}' 2>>${check_file}/error.log) | $save_result
echo -e "开机时间: \t" $((uptime | awk -F ',' '{print $1}') 2>>${check_file}/error.log) | $save_result
ip=$((ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}') 2>>${check_file}/error.log)
if [ -n "$ip" ];then
	(echo -e "IP地址为: \t" $(echo "$ip"))  | $save_result 
else
	echo -e "${RED}IP地址查询出错,请查看error.log" | $save_result
fi
echo -e "\n${NC}" | $save_result

echo -e "${YEL}-------------1.密码配置检查----------------------${NC}" | $save_result | $errorlog
echo "-------------1.1 密码复杂度检查----------------------" | $save_result | $errorlog

if [ -e "/etc/pam.d/common-password" ];then #针对 debian 系统
    pass_complexity=$(grep pam_cracklib /etc/pam.d/common-password 2>>${check_file}/error.log)
    if [ -z "$pass_complexity" ];then
        echo -e "${RED}未发现pam_cracklib的设置,可能是pam_cracklib未安装" | $save_result
    else
        echo -e "${GE}当前密码复杂度设置为: " $(echo "$pass_complexity") | $save_result
    fi
else
    if [ -e /etc/security/pwquality.conf ];then # 针对 centos 7系统
        pass_complexity=$((grep -v '#' /etc/security/pwquality.conf) 2>>${check_file}/error.log)

        echo -e "${GE}当前密码复杂度设置为:"  | $save_result
        echo -e "$pass_complexity" | $save_result
    fi
fi
echo -e "\n${NC}" | $save_result

echo "-------------1.2 密码过期策略检查----------------------" | $save_result | $errorlog
pass_expiration=$((cat /etc/login.defs | grep -v '#' | grep PASS) 2>>${check_file}/error.log)
if [ -n "$pass_expiration" ];then
    echo -e "${GE}当前密码过期策略为:"  | $save_result
    echo -e "$pass_expiration" | $save_result
else
    echo -e "${RED}检查失败,请查看error.log" | $save_result
   
fi
echo -e "\n${NC}" | $save_result

echo -e "${YEL}-------------2.用户检查----------------------${NC}" | $save_result | $errorlog
echo "-------------2.1 空口令账户检查----------------------" | $save_result | $errorlog
null_shadow=$((cat /etc/shadow | awk -F ":" '{if(length($2)==0)print$1}') 2>>${check_file}/error.log)

null_pass=$((cat /etc/passwd | awk -F ":" '{if(length($2)==0)print$1}') 2>>${check_file}/error.log)


if  [[ -z "$null_shadow" && -z "$null_pass" ]];then
    echo -e "${GE}未检查到空口令账户" | $save_result
else
    echo -e "${RED}存在空口令账户:" $(echo "$null_shadown") $(echo "$null_pass") | $save_result
fi

echo -e "\n${NC}" | $save_result

echo "-------------2.2 异常root账户检查----------------------" | $save_result | $errorlog
abnormal_root=$((cat /etc/passwd | awk -F ":" '{if($3==0 || $4==0)print$1}' | grep -v -E 'root|sync|shutdown|halt|operator') 2>>${check_file}/error.log)

if [ -z "$abnormal_root" ];then
    echo -e "${GE}未检查到异常root账户" | $save_result
else
    echo -e "${RED}存在异常root账户:" $(echo "$abnormal_root") | $save_result
fi

echo -e "\n${NC}" | $save_result

echo -e "${YEL}-------------3.日志检查----------------------${NC}" | $save_result | $errorlog
echo "-------------3.1 检查Web日志文件----------------------" | $save_result | $errorlog

echo -e "${BLUE}web日志的搜索路径为 ${web_log[@]}"

web_log_exist=""
for log in ${web_log[@]}
do
    if [ -e $log ];then
        echo -e "${GE}发现web日志文件: $log" | $save_result
        echo -e "${GE}该日志权限为: $(ls -l $log | awk '{print $1 " " $3 " " $4}' )" | $save_result
        web_log_exist="true"  
    fi
done

if [[ -z $web_log_exist ]];then
    echo -e "${RED}未发现web日志文件" | $save_result
fi

echo -e "\n${NC}" | $save_result

echo "-------------3.2 检查ssh日志文件----------------------" | $save_result | $errorlog

echo -e "${BLUE}ssh日志的搜索路径为 ${ssh_log[@]}"

ssh_log_exist=""
for log in ${ssh_log[@]}
do
    if [ -e $log ];then
        echo -e "${GE}发现ssh日志文件: $log" | $save_result
        echo -e "${GE}该日志权限为: $(ls -l $log | awk '{print $1 " " $3 " " $4}' )" | $save_result
        ssh_log_exist="true"  
    fi
done

if [[ -z $ssh_log_exist ]];then
    echo -e "${RED}未发现ssh日志文件" | $save_result
fi

echo -e "\n${NC}" | $save_result


echo -e "${YEL}-------------4.网络检查----------------------${NC}" | $save_result | $errorlog
echo "-------------4.1 检查防火墙策略----------------------" | $save_result | $errorlog

echo -e "${GE}iptables 策略显示如下" | $save_result
iptables -L 2>>${check_file}/error.log | $save_result
echo -e "\n${NC}" | $save_result

if which ufw >/dev/null 2>&1 ; then
    echo -e "${GE}ufw 策略显示如下" | $save_result
    ufw status 2>>${check_file}/error.log | $save_result
else
    echo -e "${RED}未安装ufw" | $save_result
fi
echo -e "\n${NC}" | $save_result

if which firewall-cmd  >/dev/null 2>&1; then
    echo -e "${GE}firewalld 策略显示如下" | $save_result
    firewall-cmd --list-all 2>>${check_file}/error.log | $save_result
else
    echo -e "${RED}未安装firewalld" | $save_result
fi
echo -e "\n${NC}" | $save_result

echo "-------------4.2 检查端口开放设置----------------------" | $save_result | $errorlog
echo -e "${GE}端口开放设置如下" | $save_result | $save_result 
port=$((ss -luntp | awk '{print $5}' | sed '1d') 2>>${check_file}/error.log)

echo -e "$port" | $save_result
echo -e "\n${NC}" | $save_result


grep_filter=$(echo ${examined_port[@]} | tr " " "|")
dangerous_port=$(echo -e "$port" | grep -E "0\.0\.0\.0|\*:" | grep -wE "$grep_filter")
echo -e "${BLUE}定义的危险端口为 " ${examined_port[@]} | $save_result 
if [ -z "$dangerous_port" ];then
    echo -e "${GE}未发现绑定在公网的危险端口" | $save_result
else
    echo -e "${RED}发现绑定在公网的危险端口" $dangerous_port | $save_result
fi
echo -e "\n${NC}" | $save_result

echo -e "${YEL}-------------5.文件系统检查----------------------${NC}" | $save_result 
echo "-------------5.1 检查全局可写目录----------------------" | $save_result 

echo -e "${BLUE}排除了/proc/, /sys/,/tmp/,/var/lib/目录" | $save_result 
echo -e "${GE}" | $save_result 
find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" ! -path "/tmp"  ! -path "/var/lib/*" -type d -perm -o=w 2>/dev/null | $save_result
echo -e "\n${NC}" | $save_result

echo "-------------5.2 检查全局可写文件----------------------" | $save_result 
echo -e "${BLUE}排除了/proc/, /sys/,/tmp/,/var/lib/目录" | $save_result 
echo -e "${GE}" | $save_result 
find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" ! -path "/var/lib/*" -type f -perm -o=w 2>/dev/null | $save_result
echo -e "\n${NC}" | $save_result

echo "检查完毕！！！" | $save_result 


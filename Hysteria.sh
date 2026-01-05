#!/bin/bash

# ==========================================
# Hysteria 2 + BBR 一键安装与管理脚本
# ==========================================

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

# 配置文件路径
CONFIG_FILE="/etc/hysteria/config.yaml"
CERT_FILE="/etc/hysteria/server.crt"
KEY_FILE="/etc/hysteria/server.key"

# 检查 Root 权限
[[ $EUID -ne 0 ]] && echo -e "${RED}错误：${PLAIN} 必须使用 root 用户运行此脚本！\n" && exit 1

# 1. 检查并安装 BBR
check_and_install_bbr() {
    if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf && grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo -e "${GREEN}BBR 已经开启，无需重复安装。${PLAIN}"
    else
        echo -e "${YELLOW}正在开启 BBR 加速...${PLAIN}"
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        echo -e "${GREEN}BBR 已开启！${PLAIN}"
    fi
}

# 2. 生成自签名证书
generate_cert() {
    echo -e "${YELLOW}正在生成自签名证书 (IP直连模式)...${PLAIN}"
    mkdir -p /etc/hysteria
    openssl req -x509 -nodes -newkey rsa:2048 -keyout $KEY_FILE -out $CERT_FILE -days 3650 -subj "/CN=www.bing.com" >/dev/null 2>&1
    chmod 644 $CERT_FILE
    chmod 644 $KEY_FILE
}

# 3. 生成配置文件
generate_config() {
    # 如果配置文件不存在，则生成
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}正在生成配置文件...${PLAIN}"
        PASSWORD=$(date +%s%N | md5sum | head -c 16) # 随机密码
        cat > $CONFIG_FILE <<EOF
listen: :443

tls:
  cert: $CERT_FILE
  key: $KEY_FILE

auth:
  type: password
  password: $PASSWORD

masquerade: 
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true

bandwidth:
  up: 100 mbps
  down: 100 mbps
EOF
    else
        echo -e "${YELLOW}配置文件已存在，跳过生成。${PLAIN}"
    fi
}

# 4. 创建快捷指令 h2
create_shortcut() {
    # 将当前脚本自身复制到 /usr/bin/h2
    cp "$0" /usr/bin/h2
    chmod +x /usr/bin/h2
    echo -e "${GREEN}快捷指令 'h2' 已创建/更新。${PLAIN}"
}

# 5. 安装主逻辑
install_hy2() {
    echo -e "${YELLOW}正在下载并安装 Hysteria 2...${PLAIN}"
    bash <(curl -fsSL https://get.hy2.sh/)
    
    check_and_install_bbr
    generate_cert
    generate_config
    create_shortcut
    
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server
    
    echo -e "\n${GREEN}Hysteria 2 安装完成！${PLAIN}"
    show_info
}

# 6. 卸载
uninstall_hy2() {
    read -p "确定要卸载 Hysteria 2 吗？(y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        systemctl stop hysteria-server
        systemctl disable hysteria-server
        rm -rf /etc/hysteria
        rm -f /usr/bin/h2
        # 尝试使用官方卸载方式（如果有），这里直接删除文件
        rm -f /usr/local/bin/hysteria
        echo -e "${GREEN}卸载完成。${PLAIN}"
    else
        echo "取消卸载。"
    fi
}

# 7. 显示配置信息
show_info() {
    if [ -f "$CONFIG_FILE" ]; then
        IP=$(curl -s4m8 ip.sb)
        PORT=$(grep "listen:" $CONFIG_FILE | awk '{print $2}' | sed 's/://')
        PASSWORD=$(grep "password:" $CONFIG_FILE | awk '{print $2}')
        
        echo -e "------------------------------------------------"
        echo -e "Hysteria 2 配置信息："
        echo -e "服务器 IP  : ${GREEN}${IP}${PLAIN}"
        echo -e "端口 (Port): ${GREEN}${PORT}${PLAIN}"
        echo -e "密码 (Auth): ${GREEN}${PASSWORD}${PLAIN}"
        echo -e "------------------------------------------------"
        echo -e "${YELLOW}重要提示：客户端必须开启 '允许不安全连接' (Allow Insecure/Skip Cert Verify)${PLAIN}"
    else
        echo -e "${RED}未检测到配置文件，请先安装。${PLAIN}"
    fi
}

# 8. 状态检查
check_status() {
    if systemctl is-active --quiet hysteria-server; then
        echo -e "运行状态: ${GREEN}正在运行 (Running)${PLAIN}"
    else
        echo -e "运行状态: ${RED}未运行 (Stopped)${PLAIN}"
    fi
    
    bbr_status=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    if [[ "$bbr_status" == "bbr" ]]; then
        echo -e "BBR 加速: ${GREEN}已开启${PLAIN}"
    else
        echo -e "BBR 加速: ${RED}未开启${PLAIN}"
    fi
}

# ==========================================
# 主菜单
# ==========================================
clear
echo -e "################################################"
echo -e "#         Hysteria 2 一键安装管理脚本          #"
echo -e "#          (支持 BBR + 自动证书)               #"
echo -e "################################################"
check_status
echo -e "------------------------------------------------"
echo -e " 1. 安装 Hysteria 2 (含 BBR)"
echo -e " 2. 卸载 Hysteria 2"
echo -e "------------------------------------------------"
echo -e " 3. 启动服务"
echo -e " 4. 停止服务"
echo -e " 5. 重启服务"
echo -e " 6. 查看配置信息 / 账号"
echo -e " 7. 查看运行日志"
echo -e "------------------------------------------------"
echo -e " 0. 退出脚本"
echo -e "################################################"
read -p "请输入选项 [0-7]: " num

case "$num" in
    1) install_hy2 ;;
    2) uninstall_hy2 ;;
    3) systemctl start hysteria-server && echo -e "${GREEN}已启动${PLAIN}" ;;
    4) systemctl stop hysteria-server && echo -e "${RED}已停止${PLAIN}" ;;
    5) systemctl restart hysteria-server && echo -e "${GREEN}已重启${PLAIN}" ;;
    6) show_info ;;
    7) journalctl -u hysteria-server -f ;;
    0) exit 0 ;;
    *) echo -e "${RED}请输入正确的数字${PLAIN}" ;;
esac

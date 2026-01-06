#!/bin/bash
#
# nfter - nftables 端口转发管理工具
# 运行此脚本自动检测：已安装则进入主菜单，未安装则执行安装
#

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

SERVICE_FILE="/etc/systemd/system/nfter.service"
BIN_FILE="/usr/local/bin/nfter"
#GITHUB_BASE="https://raw.githubusercontent.com/Yorkian/Nfter/main" 
GITHUB_BASE="https://ghproxy.cfd/raw.githubusercontent.com/Yorkian/Nfter/main" #开启中国加速


# 检查是否通过管道运行
is_pipe_mode() {
    # 如果标准输入不是终端，则是管道模式
    [ ! -t 0 ]
}

# 检查root权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 请使用root权限运行此脚本${NC}"
        echo "使用: sudo bash nfter.sh"
        exit 1
    fi
}

# 检查是否已安装
check_installed() {
    if [ -f "$SERVICE_FILE" ] && [ -f "$BIN_FILE" ]; then
        return 0  # 已安装
    else
        return 1  # 未安装
    fi
}

# 安装程序
install_nfter() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  nfter 安装程序${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo

    # 检查系统
    if [ ! -f /etc/debian_version ]; then
        echo -e "${YELLOW}警告: 此脚本针对Debian/Ubuntu系统设计${NC}"
        if is_pipe_mode; then
            read -p "是否继续安装? [y/N]: " confirm </dev/tty
        else
            read -p "是否继续安装? [y/N]: " confirm
        fi
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            exit 1
        fi
    fi

    # 安装nftables
    echo -e "${GREEN}[1/7] 检查并安装nftables...${NC}"
    if ! command -v nft &> /dev/null; then
        apt update
        apt install -y nftables
        echo -e "${GREEN}✓ nftables 安装完成${NC}"
    else
        echo -e "${GREEN}✓ nftables 已安装${NC}"
    fi

    # 启动nftables服务
    echo -e "${GREEN}[2/7] 启动nftables服务...${NC}"
    systemctl enable nftables
    systemctl start nftables
    echo -e "${GREEN}✓ nftables 服务已启动${NC}"

    # 启用IP转发
    echo -e "${GREEN}[3/7] 配置IP转发...${NC}"
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    fi
    sysctl -p > /dev/null 2>&1
    echo -e "${GREEN}✓ IP转发已启用${NC}"

    # 安装Python3
    echo -e "${GREEN}[4/7] 检查Python3...${NC}"
    if ! command -v python3 &> /dev/null; then
        apt install -y python3
        echo -e "${GREEN}✓ Python3 安装完成${NC}"
    else
        echo -e "${GREEN}✓ Python3 已安装${NC}"
    fi

    # 下载文件
    echo -e "${GREEN}[5/7] 下载nfter程序...${NC}"
    
    # 检查curl或wget
    if command -v curl &> /dev/null; then
        DOWNLOADER="curl -fsSL -o"
    elif command -v wget &> /dev/null; then
        DOWNLOADER="wget -q -O"
    else
        apt install -y curl
        DOWNLOADER="curl -fsSL -o"
    fi

    # 下载主程序
    $DOWNLOADER nfter.py "$GITHUB_BASE/nfter.py"
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ 下载 nfter.py 失败${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ nfter.py 下载完成${NC}"

    # 下载服务文件
    $DOWNLOADER nfter.service "$GITHUB_BASE/nfter.service"
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ 下载 nfter.service 失败${NC}"
        rm -f nfter.py
        exit 1
    fi
    echo -e "${GREEN}✓ nfter.service 下载完成${NC}"

    # 安装主程序
    echo -e "${GREEN}[6/7] 安装nfter...${NC}"
    cp nfter.py "$BIN_FILE"
    chmod +x "$BIN_FILE"
    mkdir -p /etc/nfter
    echo -e "${GREEN}✓ nfter 已安装到 $BIN_FILE${NC}"

    # 安装systemd服务
    echo -e "${GREEN}[7/7] 安装域名监控服务...${NC}"
    cp nfter.service "$SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${GREEN}✓ systemd 服务已安装${NC}"

    # 清理下载的文件
    rm -f nfter.py nfter.service

    echo
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  安装完成！${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo
    echo "使用方法:"
    echo -e "  ${YELLOW}sudo nfter${NC}              # 启动交互界面"
    echo -e "  ${YELLOW}sudo bash nfter.sh${NC}      # 或运行此脚本"
    echo
    echo "域名监控服务:"
    echo -e "  ${YELLOW}sudo systemctl enable --now nfter${NC}  # 启动并开机自启"
    echo
    
    # 自动进入主菜单
    if is_pipe_mode; then
        # 管道模式下重定向输入到终端
        exec "$BIN_FILE" </dev/tty
    else
        # 交互模式
        read -p "是否立即进入主菜单? [Y/n]: " enter_menu
        if [ "$enter_menu" != "n" ] && [ "$enter_menu" != "N" ]; then
            exec "$BIN_FILE"
        fi
    fi
}

# 主逻辑
main() {
    check_root
    
    if check_installed; then
        # 已安装，直接运行nfter
        if is_pipe_mode; then
            # 管道模式下重定向输入到终端
            exec "$BIN_FILE" </dev/tty
        else
            exec "$BIN_FILE"
        fi
    else
        # 未安装，执行安装
        install_nfter
    fi
}

main

#!/usr/bin/env python3
"""
nfter - nftables 端口转发管理工具
支持单端口、多端口转发，支持IPv4和IPv6目标，支持域名动态解析
适用于 Debian 系统
"""

import subprocess
import sys
import re
import ipaddress
import os
import json
import socket
import time
import signal
from datetime import datetime

# 配置文件路径
CONFIG_FILE = "/etc/nfter/domains.json"
PID_FILE = "/var/run/nfter-daemon.pid"
LOG_FILE = "/var/log/nfter.log"

# 颜色定义
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def print_color(text, color):
    """打印彩色文本"""
    print(f"{color}{text}{Colors.ENDC}")

def print_header(text):
    """打印标题"""
    print()
    print_color("=" * 60, Colors.CYAN)
    print_color(f"  {text}", Colors.CYAN + Colors.BOLD)
    print_color("=" * 60, Colors.CYAN)
    print()

def print_success(text):
    print_color(f"✓ {text}", Colors.GREEN)

def print_error(text):
    print_color(f"✗ {text}", Colors.RED)

def print_warning(text):
    print_color(f"⚠ {text}", Colors.YELLOW)

def print_info(text):
    print_color(f"ℹ {text}", Colors.BLUE)

def get_display_width(text):
    """计算字符串的显示宽度（中文字符占2个宽度）"""
    width = 0
    for char in str(text):
        if '\u4e00' <= char <= '\u9fff' or \
           '\u3000' <= char <= '\u303f' or \
           '\uff00' <= char <= '\uffef':
            width += 2
        else:
            width += 1
    return width

def pad_to_width(text, target_width, align='center'):
    """将字符串填充到指定显示宽度"""
    text = str(text)
    current_width = get_display_width(text)
    padding_needed = target_width - current_width
    
    if padding_needed <= 0:
        return text
    
    if align == 'center':
        left_pad = padding_needed // 2
        right_pad = padding_needed - left_pad
        return ' ' * left_pad + text + ' ' * right_pad
    elif align == 'left':
        return text + ' ' * padding_needed
    else:  # right
        return ' ' * padding_needed + text

def format_bytes(bytes_count):
    """格式化字节数为人类可读格式"""
    try:
        bytes_count = int(bytes_count)
    except (ValueError, TypeError):
        return "0 B"
    
    if bytes_count < 1024:
        return f"{bytes_count} B"
    elif bytes_count < 1024 * 1024:
        return f"{bytes_count / 1024:.1f} KB"
    elif bytes_count < 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_count / (1024 * 1024 * 1024):.2f} GB"

def format_packets(packets_count):
    """格式化包数量"""
    try:
        packets_count = int(packets_count)
    except (ValueError, TypeError):
        return "0"
    
    if packets_count < 1000:
        return str(packets_count)
    elif packets_count < 1000000:
        return f"{packets_count / 1000:.1f}K"
    else:
        return f"{packets_count / 1000000:.1f}M"

def run_cmd(cmd, capture=True):
    """运行命令并返回结果"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=capture, 
            text=True,
            timeout=30
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "命令执行超时"
    except Exception as e:
        return False, "", str(e)

def check_root():
    """检查是否以root权限运行"""
    if os.geteuid() != 0:
        print_error("此工具需要root权限运行！")
        print_info("请使用 sudo nfter 运行")
        sys.exit(1)

def check_nftables():
    """检查nftables是否已安装"""
    success, _, _ = run_cmd("which nft")
    if not success:
        print_error("nftables 未安装！")
        print_info("请运行: apt install nftables")
        sys.exit(1)
    
    # 检查nftables服务状态
    success, _, _ = run_cmd("systemctl is-active nftables")
    if not success:
        print_warning("nftables服务未运行，正在启动...")
        run_cmd("systemctl start nftables")
        run_cmd("systemctl enable nftables")

def init_nat_table():
    """初始化NAT表和链（如果不存在）"""
    success, stdout, _ = run_cmd("nft list tables")
    
    # 创建 ip nat 表 (用于IPv4)
    if "table ip nat" not in stdout:
        run_cmd("nft add table ip nat")
    
    # 创建 ip6 nat 表 (用于IPv6)
    if "table ip6 nat" not in stdout:
        run_cmd("nft add table ip6 nat")
    
    # 检查并创建 prerouting 链 (IPv4)
    success, stdout, _ = run_cmd("nft list chain ip nat prerouting 2>/dev/null")
    if not success:
        run_cmd("nft add chain ip nat prerouting { type nat hook prerouting priority -100 \\; }")
    
    # 检查并创建 postrouting 链 (IPv4)
    success, stdout, _ = run_cmd("nft list chain ip nat postrouting 2>/dev/null")
    if not success:
        run_cmd("nft add chain ip nat postrouting { type nat hook postrouting priority 100 \\; }")
    
    # 检查并创建 prerouting 链 (IPv6)
    success, stdout, _ = run_cmd("nft list chain ip6 nat prerouting 2>/dev/null")
    if not success:
        run_cmd("nft add chain ip6 nat prerouting { type nat hook prerouting priority -100 \\; }")
    
    # 检查并创建 postrouting 链 (IPv6)
    success, stdout, _ = run_cmd("nft list chain ip6 nat postrouting 2>/dev/null")
    if not success:
        run_cmd("nft add chain ip6 nat postrouting { type nat hook postrouting priority 100 \\; }")
    
    # 启用IP转发
    run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    run_cmd("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")
    
    # 确保配置目录存在
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

def validate_ip(ip_str):
    """验证IP地址，返回 (是否有效, IP版本)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return True, ip.version
    except ValueError:
        return False, None

def validate_port(port_str):
    """验证端口号"""
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False

def resolve_domain(domain):
    """解析域名为IP地址，返回 (IP, 版本) 或 (None, None)"""
    try:
        # 先尝试获取IPv4
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        if result:
            ip = result[0][4][0]
            return ip, 4
    except socket.gaierror:
        pass
    
    try:
        # 再尝试获取IPv6
        result = socket.getaddrinfo(domain, None, socket.AF_INET6)
        if result:
            ip = result[0][4][0]
            return ip, 6
    except socket.gaierror:
        pass
    
    return None, None

def validate_target(target_str):
    """验证目标地址（IP或域名），返回 (是否有效, IP地址, IP版本, 是否域名)"""
    # 先检查是否是有效IP
    valid, version = validate_ip(target_str)
    if valid:
        return True, target_str, version, False
    
    # 尝试解析为域名
    ip, version = resolve_domain(target_str)
    if ip:
        return True, ip, version, True
    
    return False, None, None, False

def get_input(prompt, validator=None, error_msg="输入无效，请重试", default=None):
    """获取用户输入并验证，支持默认值"""
    while True:
        if default is not None:
            display_prompt = f"{Colors.CYAN}{prompt} [默认: {default}]: {Colors.ENDC}"
        else:
            display_prompt = f"{Colors.CYAN}{prompt}: {Colors.ENDC}"
        
        value = input(display_prompt).strip()
        
        if value.lower() == 'q':
            return None
        
        if value == '' and default is not None:
            return default
        
        if value == '' and default is None:
            print_error(error_msg)
            continue
            
        if validator is None or validator(value):
            return value
        print_error(error_msg)

# ==================== 域名配置管理 ====================

def load_domain_config():
    """加载域名配置"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            return {"mappings": []}
    return {"mappings": []}

def save_domain_config(config):
    """保存域名配置"""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def add_domain_mapping(domain, current_ip, ip_version, local_port, target_port, protocols, handles):
    """添加域名映射记录"""
    config = load_domain_config()
    
    mapping = {
        "domain": domain,
        "current_ip": current_ip,
        "ip_version": ip_version,
        "local_port": local_port,
        "target_port": target_port,
        "protocols": protocols,
        "handles": handles,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    config["mappings"].append(mapping)
    save_domain_config(config)

def remove_domain_mapping_by_handle(handle):
    """根据handle删除域名映射"""
    config = load_domain_config()
    new_mappings = []
    for m in config["mappings"]:
        if handle not in m.get("handles", []):
            new_mappings.append(m)
    config["mappings"] = new_mappings
    save_domain_config(config)

def update_domain_ip():
    """更新所有域名的IP地址（供守护进程调用）"""
    config = load_domain_config()
    updated = False
    
    for mapping in config["mappings"]:
        domain = mapping.get("domain")
        if not domain:
            continue
        
        new_ip, new_version = resolve_domain(domain)
        if not new_ip:
            log_message(f"无法解析域名: {domain}")
            continue
        
        old_ip = mapping.get("current_ip")
        if new_ip != old_ip:
            log_message(f"域名 {domain} IP变化: {old_ip} -> {new_ip}")
            
            # 更新规则
            success = update_rule_ip(mapping, new_ip, new_version)
            if success:
                mapping["current_ip"] = new_ip
                mapping["ip_version"] = new_version
                mapping["updated_at"] = datetime.now().isoformat()
                updated = True
                log_message(f"规则更新成功: {domain} -> {new_ip}")
            else:
                log_message(f"规则更新失败: {domain}")
    
    if updated:
        save_domain_config(config)

def update_rule_ip(mapping, new_ip, new_version):
    """更新规则中的IP地址"""
    local_port = mapping.get("local_port")
    target_port = mapping.get("target_port")
    protocols = mapping.get("protocols", [])
    old_handles = mapping.get("handles", [])
    
    table = "ip" if new_version == 4 else "ip6"
    new_handles = []
    
    # 删除旧规则
    for handle in old_handles:
        run_cmd(f"nft delete rule ip nat prerouting handle {handle} 2>/dev/null")
        run_cmd(f"nft delete rule ip6 nat prerouting handle {handle} 2>/dev/null")
    
    # 添加新规则
    for proto in protocols:
        if new_version == 4:
            dnat_cmd = f"nft add rule {table} nat prerouting {proto} dport {local_port} counter dnat to {new_ip}:{target_port}"
        else:
            dnat_cmd = f"nft add rule {table} nat prerouting {proto} dport {local_port} counter dnat to [{new_ip}]:{target_port}"
        
        success, _, _ = run_cmd(dnat_cmd)
        if success:
            # 获取新的handle
            success, stdout, _ = run_cmd(f"nft -a list chain {table} nat prerouting | grep '{proto} dport {local_port}' | grep -oP 'handle \\d+' | tail -1")
            if success:
                handle_match = re.search(r'handle (\d+)', stdout)
                if handle_match:
                    new_handles.append(handle_match.group(1))
    
    mapping["handles"] = new_handles
    
    # 保存规则
    run_cmd("nft list ruleset > /etc/nftables.conf.tmp && mv /etc/nftables.conf.tmp /etc/nftables.conf")
    
    return len(new_handles) > 0

def log_message(message):
    """写入日志"""
    try:
        with open(LOG_FILE, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except:
        pass

# ==================== 守护进程管理 ====================

def daemon_loop():
    """守护进程主循环"""
    log_message("守护进程启动")
    
    while True:
        try:
            update_domain_ip()
        except Exception as e:
            log_message(f"更新出错: {str(e)}")
        
        # 每10分钟检查一次
        time.sleep(600)

def start_daemon():
    """启动守护进程"""
    # 检查是否已运行
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            print_warning(f"守护进程已在运行 (PID: {pid})")
            return
        except (OSError, ValueError):
            os.remove(PID_FILE)
    
    # Fork进程
    pid = os.fork()
    if pid > 0:
        print_success(f"守护进程已启动 (PID: {pid})")
        return
    
    # 子进程
    os.setsid()
    os.umask(0)
    
    # 再次fork
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    
    # 重定向标准输入输出
    sys.stdin.close()
    sys.stdout.close()
    sys.stderr.close()
    
    # 保存PID
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))
    
    # 运行守护循环
    daemon_loop()

def stop_daemon():
    """停止守护进程"""
    if not os.path.exists(PID_FILE):
        print_info("守护进程未运行")
        return
    
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        os.remove(PID_FILE)
        print_success("守护进程已停止")
    except (OSError, ValueError) as e:
        print_error(f"停止守护进程失败: {e}")
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

def daemon_status():
    """检查守护进程状态"""
    if not os.path.exists(PID_FILE):
        return False, None
    
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True, pid
    except (OSError, ValueError):
        return False, None

# ==================== 规则解析 ====================

def parse_forward_rules():
    """解析所有转发规则，返回规则列表"""
    rules = []
    rule_id = 1
    
    # 加载域名配置用于显示
    domain_config = load_domain_config()
    handle_to_domain = {}
    for m in domain_config.get("mappings", []):
        for h in m.get("handles", []):
            handle_to_domain[h] = m.get("domain", "")
    
    # 解析 IPv4 规则
    success, stdout, _ = run_cmd("nft -a list chain ip nat prerouting 2>/dev/null")
    if success:
        for line in stdout.split('\n'):
            if 'dnat to' in line:
                rule = parse_single_rule(line, 'IPv4', rule_id, handle_to_domain)
                if rule:
                    rules.append(rule)
                    rule_id += 1
    
    # 解析 IPv6 规则
    success, stdout, _ = run_cmd("nft -a list chain ip6 nat prerouting 2>/dev/null")
    if success:
        for line in stdout.split('\n'):
            if 'dnat to' in line:
                rule = parse_single_rule(line, 'IPv6', rule_id, handle_to_domain)
                if rule:
                    rules.append(rule)
                    rule_id += 1
    
    return rules

def parse_single_rule(line, ip_version, rule_id, handle_to_domain=None):
    """解析单条规则"""
    rule = {
        'id': rule_id,
        'ip_version': ip_version,
        'protocol': '',
        'local_port': '',
        'target_ip': '',
        'target_port': '',
        'handle': '',
        'packets': 0,
        'bytes': 0,
        'domain': '',
        'raw': line.strip()
    }
    
    # 提取协议
    line_lower = line.lower()
    if 'tcp dport' in line_lower or 'tcp sport' in line_lower:
        rule['protocol'] = 'TCP'
    elif 'udp dport' in line_lower or 'udp sport' in line_lower:
        rule['protocol'] = 'UDP'
    elif ' tcp ' in line_lower:
        rule['protocol'] = 'TCP'
    elif ' udp ' in line_lower:
        rule['protocol'] = 'UDP'
    else:
        rule['protocol'] = 'ALL'
    
    # 提取本地端口 (dport)
    dport_match = re.search(r'dport\s+(\d+(?:-\d+)?)', line)
    if dport_match:
        rule['local_port'] = dport_match.group(1)
    
    # 提取流量统计 - packets X bytes Y
    counter_match = re.search(r'packets\s+(\d+)\s+bytes\s+(\d+)', line)
    if counter_match:
        rule['packets'] = int(counter_match.group(1))
        rule['bytes'] = int(counter_match.group(2))
    
    # 提取目标地址和端口
    if ip_version == 'IPv4':
        dnat_match = re.search(r'dnat to\s+([\d.]+)(?::(\d+(?:-\d+)?))?', line)
        if dnat_match:
            rule['target_ip'] = dnat_match.group(1)
            rule['target_port'] = dnat_match.group(2) if dnat_match.group(2) else rule['local_port']
    else:
        dnat_match = re.search(r'dnat to\s+\[([^\]]+)\](?::(\d+(?:-\d+)?))?', line)
        if dnat_match:
            rule['target_ip'] = dnat_match.group(1)
            rule['target_port'] = dnat_match.group(2) if dnat_match.group(2) else rule['local_port']
        else:
            dnat_match = re.search(r'dnat to\s+([0-9a-fA-F:]+)', line)
            if dnat_match:
                rule['target_ip'] = dnat_match.group(1)
                rule['target_port'] = rule['local_port']
    
    # 提取 handle
    handle_match = re.search(r'handle\s+(\d+)', line)
    if handle_match:
        rule['handle'] = handle_match.group(1)
        # 查找对应的域名
        if handle_to_domain and rule['handle'] in handle_to_domain:
            rule['domain'] = handle_to_domain[rule['handle']]
    
    if rule['local_port'] and rule['target_ip']:
        return rule
    return None

def print_rules_table(rules):
    """以表格形式打印规则"""
    if not rules:
        print_info("当前没有端口转发规则")
        return
    
    # 表格标题
    headers = ['编号', '协议', '本地端口', '目标地址', '目标端口', '流量', 'IP版本']
    
    # 准备数据，生成流量显示字符串
    for rule in rules:
        traffic = f"{format_packets(rule['packets'])}包/{format_bytes(rule['bytes'])}"
        rule['traffic_display'] = traffic
        # 如果有域名，显示域名
        if rule['domain']:
            rule['target_display'] = f"{rule['domain']}"
        else:
            rule['target_display'] = rule['target_ip']
    
    # 计算每列所需的显示宽度
    col_widths = []
    
    # 编号列
    col_widths.append(max(
        get_display_width(headers[0]),
        max(get_display_width(str(r['id'])) for r in rules)
    ) + 2)
    
    # 协议列
    col_widths.append(max(
        get_display_width(headers[1]),
        max(get_display_width(r['protocol']) for r in rules)
    ) + 2)
    
    # 本地端口列
    col_widths.append(max(
        get_display_width(headers[2]),
        max(get_display_width(r['local_port']) for r in rules)
    ) + 2)
    
    # 目标地址列
    col_widths.append(max(
        get_display_width(headers[3]),
        max(get_display_width(r['target_display']) for r in rules)
    ) + 2)
    
    # 目标端口列
    col_widths.append(max(
        get_display_width(headers[4]),
        max(get_display_width(r['target_port']) for r in rules)
    ) + 2)
    
    # 流量列
    col_widths.append(max(
        get_display_width(headers[5]),
        max(get_display_width(r['traffic_display']) for r in rules)
    ) + 2)
    
    # IP版本列
    col_widths.append(max(
        get_display_width(headers[6]),
        max(get_display_width(r['ip_version']) for r in rules)
    ) + 2)
    
    # 顶部边框
    print_color("┌" + "┬".join("─" * w for w in col_widths) + "┐", Colors.CYAN)
    
    # 标题行
    header_row = "│"
    for i, h in enumerate(headers):
        header_row += pad_to_width(h, col_widths[i]) + "│"
    print_color(header_row, Colors.CYAN + Colors.BOLD)
    
    # 标题分隔线
    print_color("├" + "┼".join("─" * w for w in col_widths) + "┤", Colors.CYAN)
    
    # 数据行
    for rule in rules:
        row = "│"
        row += pad_to_width(str(rule['id']), col_widths[0]) + "│"
        row += pad_to_width(rule['protocol'], col_widths[1]) + "│"
        row += pad_to_width(rule['local_port'], col_widths[2]) + "│"
        row += pad_to_width(rule['target_display'], col_widths[3]) + "│"
        row += pad_to_width(rule['target_port'], col_widths[4]) + "│"
        row += pad_to_width(rule['traffic_display'], col_widths[5]) + "│"
        row += pad_to_width(rule['ip_version'], col_widths[6]) + "│"
        print(row)
    
    # 底部边框
    print_color("└" + "┴".join("─" * w for w in col_widths) + "┘", Colors.CYAN)
    
    print()
    
    # 统计总流量
    total_packets = sum(r['packets'] for r in rules)
    total_bytes = sum(r['bytes'] for r in rules)
    print_info(f"共 {len(rules)} 条转发规则 | 总流量: {format_packets(total_packets)} 包 / {format_bytes(total_bytes)}")

def show_rules():
    """显示当前的端口转发规则"""
    print_header("当前端口转发规则")
    
    rules = parse_forward_rules()
    print_rules_table(rules)
    
    # 显示域名监控状态
    running, pid = daemon_status()
    if running:
        print_info(f"域名监控服务运行中 (PID: {pid})")
    else:
        config = load_domain_config()
        if config.get("mappings"):
            print_warning("域名监控服务未运行，域名IP变化将不会自动更新")

def add_single_port_forward():
    """添加单端口转发"""
    print_header("添加单端口转发")
    print_info("输入 'q' 可随时返回主菜单")
    print_info("目标地址支持IP地址或域名\n")
    
    # 选择协议
    print("选择协议:")
    print("  1. TCP")
    print("  2. UDP")
    print("  3. TCP + UDP")
    protocol_choice = get_input(
        "请选择 [1-3]",
        lambda x: x in ['1', '2', '3'],
        "请输入 1、2 或 3",
        default='3'
    )
    if protocol_choice is None:
        return
    
    protocols = []
    if protocol_choice == '1':
        protocols = ['tcp']
    elif protocol_choice == '2':
        protocols = ['udp']
    else:
        protocols = ['tcp', 'udp']
    
    # 输入本地端口
    local_port = get_input(
        "本地监听端口",
        validate_port,
        "端口必须是1-65535之间的数字"
    )
    if local_port is None:
        return
    
    # 输入目标地址（IP或域名）
    target_input = get_input(
        "目标地址 (IP或域名)",
        lambda x: validate_target(x)[0],
        "请输入有效的IP地址或可解析的域名"
    )
    if target_input is None:
        return
    
    valid, target_ip, ip_version, is_domain = validate_target(target_input)
    
    if is_domain:
        print_info(f"域名 {target_input} 解析为 {target_ip}")
    
    # 输入目标端口
    target_port = get_input(
        "目标端口",
        lambda x: x == '' or validate_port(x),
        "端口必须是1-65535之间的数字",
        default=local_port
    )
    if target_port is None:
        return
    
    # 确认信息
    print()
    print_color("即将添加以下转发规则:", Colors.YELLOW)
    print(f"  协议: {', '.join(protocols).upper()}")
    print(f"  本地端口: {local_port}")
    if is_domain:
        print(f"  目标域名: {target_input}")
        print(f"  当前解析IP: {target_ip}")
    else:
        print(f"  目标地址: {target_ip}")
    print(f"  目标端口: {target_port}")
    print(f"  IP版本: IPv{ip_version}")
    if is_domain:
        print_info("域名IP变化时将自动更新规则（需启动守护进程）")
    print()
    
    confirm = input(f"{Colors.CYAN}确认添加？[Y/n]: {Colors.ENDC}").strip().lower()
    if confirm == 'n':
        print_warning("已取消操作")
        return
    
    # 执行添加
    table = "ip" if ip_version == 4 else "ip6"
    success_count = 0
    handles = []
    
    for proto in protocols:
        if ip_version == 4:
            dnat_cmd = f"nft add rule {table} nat prerouting {proto} dport {local_port} counter dnat to {target_ip}:{target_port}"
        else:
            dnat_cmd = f"nft add rule {table} nat prerouting {proto} dport {local_port} counter dnat to [{target_ip}]:{target_port}"
        
        success, _, stderr = run_cmd(dnat_cmd)
        if success:
            success_count += 1
            # 获取handle
            success2, stdout, _ = run_cmd(f"nft -a list chain {table} nat prerouting | grep '{proto} dport {local_port}' | grep -oP 'handle \\d+' | tail -1")
            if success2:
                handle_match = re.search(r'handle (\d+)', stdout)
                if handle_match:
                    handles.append(handle_match.group(1))
        else:
            print_error(f"添加 {proto.upper()} DNAT规则失败: {stderr}")
        
        # MASQUERADE规则
        masq_cmd = f"nft add rule {table} nat postrouting {proto} dport {target_port} counter masquerade"
        run_cmd(masq_cmd)
    
    if success_count > 0:
        print_success(f"成功添加 {success_count} 条转发规则")
        
        # 如果是域名，保存映射关系
        if is_domain:
            add_domain_mapping(target_input, target_ip, ip_version, local_port, target_port, protocols, handles)
            print_info(f"已保存域名映射，将每10分钟检查IP变化")
            
            # 提示启动守护进程
            running, _ = daemon_status()
            if not running:
                start = input(f"{Colors.CYAN}是否启动域名监控服务？[Y/n]: {Colors.ENDC}").strip().lower()
                if start != 'n':
                    start_daemon()
        
        save_rules_prompt()

def add_port_range_forward():
    """添加端口范围转发"""
    print_header("添加端口范围转发")
    print_info("输入 'q' 可随时返回主菜单")
    print_info("目标地址支持IP地址或域名\n")
    
    # 选择协议
    print("选择协议:")
    print("  1. TCP")
    print("  2. UDP")
    print("  3. TCP + UDP")
    protocol_choice = get_input(
        "请选择 [1-3]",
        lambda x: x in ['1', '2', '3'],
        "请输入 1、2 或 3",
        default='3'
    )
    if protocol_choice is None:
        return
    
    protocols = []
    if protocol_choice == '1':
        protocols = ['tcp']
    elif protocol_choice == '2':
        protocols = ['udp']
    else:
        protocols = ['tcp', 'udp']
    
    # 输入起始端口
    start_port = get_input(
        "本地起始端口",
        validate_port,
        "端口必须是1-65535之间的数字"
    )
    if start_port is None:
        return
    
    # 输入结束端口
    end_port = get_input(
        "本地结束端口",
        lambda x: validate_port(x) and int(x) >= int(start_port),
        f"端口必须是{start_port}-65535之间的数字"
    )
    if end_port is None:
        return
    
    # 输入目标地址
    target_input = get_input(
        "目标地址 (IP或域名)",
        lambda x: validate_target(x)[0],
        "请输入有效的IP地址或可解析的域名"
    )
    if target_input is None:
        return
    
    valid, target_ip, ip_version, is_domain = validate_target(target_input)
    
    if is_domain:
        print_info(f"域名 {target_input} 解析为 {target_ip}")
    
    # 选择端口映射方式
    print()
    print("端口映射方式:")
    print("  1. 保持原端口 (本地端口1000-1100 -> 目标端口1000-1100)")
    print("  2. 指定目标起始端口 (本地端口1000-1100 -> 目标端口2000-2100)")
    mapping_choice = get_input(
        "请选择 [1-2]",
        lambda x: x in ['1', '2'],
        "请输入 1 或 2",
        default='1'
    )
    if mapping_choice is None:
        return
    
    if mapping_choice == '1':
        target_start_port = start_port
    else:
        target_start_port = get_input(
            "目标起始端口",
            validate_port,
            "端口必须是1-65535之间的数字"
        )
        if target_start_port is None:
            return
    
    # 计算目标结束端口
    port_count = int(end_port) - int(start_port)
    target_end_port = int(target_start_port) + port_count
    
    if target_end_port > 65535:
        print_error(f"目标端口范围超出限制 (结束端口: {target_end_port} > 65535)")
        return
    
    # 确认信息
    print()
    print_color("即将添加以下转发规则:", Colors.YELLOW)
    print(f"  协议: {', '.join(protocols).upper()}")
    print(f"  本地端口范围: {start_port}-{end_port}")
    if is_domain:
        print(f"  目标域名: {target_input}")
        print(f"  当前解析IP: {target_ip}")
    else:
        print(f"  目标地址: {target_ip}")
    print(f"  目标端口范围: {target_start_port}-{target_end_port}")
    print(f"  IP版本: IPv{ip_version}")
    print()
    
    confirm = input(f"{Colors.CYAN}确认添加？[Y/n]: {Colors.ENDC}").strip().lower()
    if confirm == 'n':
        print_warning("已取消操作")
        return
    
    # 执行添加
    table = "ip" if ip_version == 4 else "ip6"
    success_count = 0
    handles = []
    local_port_str = f"{start_port}-{end_port}"
    target_port_str = f"{target_start_port}-{target_end_port}" if target_start_port != start_port else local_port_str
    
    for proto in protocols:
        if ip_version == 4:
            if start_port == target_start_port:
                dnat_cmd = f"nft add rule {table} nat prerouting {proto} dport {start_port}-{end_port} counter dnat to {target_ip}"
            else:
                dnat_cmd = f"nft add rule {table} nat prerouting {proto} dport {start_port}-{end_port} counter dnat to {target_ip}:{target_start_port}-{target_end_port}"
        else:
            if start_port == target_start_port:
                dnat_cmd = f"nft add rule {table} nat prerouting {proto} dport {start_port}-{end_port} counter dnat to {target_ip}"
            else:
                dnat_cmd = f"nft add rule {table} nat prerouting {proto} dport {start_port}-{end_port} counter dnat to [{target_ip}]:{target_start_port}-{target_end_port}"
        
        success, _, stderr = run_cmd(dnat_cmd)
        if success:
            success_count += 1
            # 获取handle
            success2, stdout, _ = run_cmd(f"nft -a list chain {table} nat prerouting | grep '{proto} dport {start_port}-{end_port}' | grep -oP 'handle \\d+' | tail -1")
            if success2:
                handle_match = re.search(r'handle (\d+)', stdout)
                if handle_match:
                    handles.append(handle_match.group(1))
        else:
            print_error(f"添加 {proto.upper()} DNAT规则失败: {stderr}")
        
        # MASQUERADE规则
        masq_cmd = f"nft add rule {table} nat postrouting {proto} dport {target_start_port}-{target_end_port} counter masquerade"
        run_cmd(masq_cmd)
    
    if success_count > 0:
        print_success(f"成功添加 {success_count} 条端口范围转发规则")
        
        # 如果是域名，保存映射关系
        if is_domain:
            add_domain_mapping(target_input, target_ip, ip_version, local_port_str, target_port_str, protocols, handles)
            print_info(f"已保存域名映射，将每10分钟检查IP变化")
            
            running, _ = daemon_status()
            if not running:
                start = input(f"{Colors.CYAN}是否启动域名监控服务？[Y/n]: {Colors.ENDC}").strip().lower()
                if start != 'n':
                    start_daemon()
        
        save_rules_prompt()

def delete_rule():
    """删除规则"""
    print_header("删除转发规则")
    
    rules = parse_forward_rules()
    
    if not rules:
        print_info("当前没有可删除的转发规则")
        return
    
    print_rules_table(rules)
    
    print_info("输入 'q' 返回主菜单\n")
    
    rule_id = get_input(
        "请输入要删除的规则编号",
        lambda x: x.isdigit() and 1 <= int(x) <= len(rules),
        f"请输入 1-{len(rules)} 之间的数字"
    )
    if rule_id is None:
        return
    
    rule = rules[int(rule_id) - 1]
    
    print()
    print_color("即将删除以下规则:", Colors.YELLOW)
    print(f"  协议: {rule['protocol']}")
    print(f"  本地端口: {rule['local_port']}")
    if rule['domain']:
        print(f"  目标域名: {rule['domain']}")
    print(f"  目标地址: {rule['target_ip']}:{rule['target_port']}")
    print(f"  已用流量: {format_packets(rule['packets'])} 包 / {format_bytes(rule['bytes'])}")
    print(f"  IP版本: {rule['ip_version']}")
    print()
    
    confirm = input(f"{Colors.CYAN}确认删除？[y/N]: {Colors.ENDC}").strip().lower()
    if confirm != 'y':
        print_warning("已取消操作")
        return
    
    table = "ip" if rule['ip_version'] == 'IPv4' else "ip6"
    cmd = f"nft delete rule {table} nat prerouting handle {rule['handle']}"
    success, _, stderr = run_cmd(cmd)
    
    if success:
        # 删除域名映射
        if rule['handle']:
            remove_domain_mapping_by_handle(rule['handle'])
        print_success("规则删除成功")
        save_rules_prompt()
    else:
        print_error(f"删除失败: {stderr}")

def flush_rules():
    """清空所有规则"""
    print_header("清空所有转发规则")
    
    rules = parse_forward_rules()
    if not rules:
        print_info("当前没有转发规则")
        return
    
    print_rules_table(rules)
    
    print_warning("此操作将删除上述所有NAT规则！")
    
    confirm = input(f"{Colors.RED}确认清空所有规则？请输入 'yes' 确认: {Colors.ENDC}").strip().lower()
    if confirm != 'yes':
        print_warning("已取消操作")
        return
    
    run_cmd("nft flush table ip nat")
    run_cmd("nft flush table ip6 nat")
    
    # 清空域名配置
    save_domain_config({"mappings": []})
    
    print_success("所有NAT规则已清空")
    
    init_nat_table()
    print_info("已重新初始化NAT链")
    save_rules_prompt()

def save_rules():
    """保存规则到文件"""
    success, stdout, _ = run_cmd("nft list ruleset")
    if success:
        with open("/etc/nftables.conf", "w") as f:
            f.write("#!/usr/sbin/nft -f\n\n")
            f.write("flush ruleset\n\n")
            f.write(stdout)
        print_success("规则已保存到 /etc/nftables.conf")
        print_info("规则将在系统重启后自动加载")
    else:
        print_error("保存规则失败")

def save_rules_prompt():
    """询问是否保存规则"""
    save = input(f"\n{Colors.CYAN}是否保存规则以便重启后生效？[Y/n]: {Colors.ENDC}").strip().lower()
    if save != 'n':
        save_rules()

def manage_daemon():
    """管理守护进程"""
    print_header("域名监控服务管理")
    
    running, pid = daemon_status()
    
    if running:
        print_success(f"服务状态: 运行中 (PID: {pid})")
    else:
        print_warning("服务状态: 未运行")
    
    # 显示域名映射
    config = load_domain_config()
    mappings = config.get("mappings", [])
    
    if mappings:
        print()
        print_color("当前域名映射:", Colors.YELLOW)
        for m in mappings:
            print(f"  {m['domain']} -> {m['current_ip']} (端口 {m['local_port']} -> {m['target_port']})")
            print(f"    更新时间: {m.get('updated_at', 'N/A')}")
    
    print()
    print("操作选项:")
    print("  1. 启动服务")
    print("  2. 停止服务")
    print("  3. 重启服务")
    print("  4. 立即更新域名IP")
    print("  5. 查看日志")
    print("  0. 返回")
    print()
    
    choice = get_input("请选择", lambda x: x in ['0', '1', '2', '3', '4', '5'], "请输入 0-5")
    if choice is None or choice == '0':
        return
    
    if choice == '1':
        start_daemon()
    elif choice == '2':
        stop_daemon()
    elif choice == '3':
        stop_daemon()
        time.sleep(1)
        start_daemon()
    elif choice == '4':
        print_info("正在更新域名IP...")
        update_domain_ip()
        print_success("更新完成")
    elif choice == '5':
        if os.path.exists(LOG_FILE):
            success, stdout, _ = run_cmd(f"tail -50 {LOG_FILE}")
            if success:
                print()
                print_color("最近日志:", Colors.YELLOW)
                print(stdout)
        else:
            print_info("日志文件不存在")

def show_status():
    """显示系统状态"""
    print_header("系统状态")
    
    # IP转发状态
    success, stdout, _ = run_cmd("cat /proc/sys/net/ipv4/ip_forward")
    ipv4_forward = stdout.strip() == '1'
    success, stdout, _ = run_cmd("cat /proc/sys/net/ipv6/conf/all/forwarding")
    ipv6_forward = stdout.strip() == '1'
    
    print_color("【IP转发状态】", Colors.YELLOW + Colors.BOLD)
    print(f"  IPv4 转发: {'✓ 已启用' if ipv4_forward else '✗ 未启用'}")
    print(f"  IPv6 转发: {'✓ 已启用' if ipv6_forward else '✗ 未启用'}")
    print()
    
    # nftables服务状态
    success, stdout, _ = run_cmd("systemctl is-active nftables")
    nft_active = stdout.strip() == 'active'
    
    print_color("【nftables服务】", Colors.YELLOW + Colors.BOLD)
    print(f"  服务状态: {'✓ 运行中' if nft_active else '✗ 未运行'}")
    
    # 守护进程状态
    running, pid = daemon_status()
    print()
    print_color("【域名监控服务】", Colors.YELLOW + Colors.BOLD)
    if running:
        print(f"  服务状态: ✓ 运行中 (PID: {pid})")
    else:
        print(f"  服务状态: ✗ 未运行")
    
    # 规则统计
    rules = parse_forward_rules()
    ipv4_count = sum(1 for r in rules if r['ip_version'] == 'IPv4')
    ipv6_count = sum(1 for r in rules if r['ip_version'] == 'IPv6')
    total_packets = sum(r['packets'] for r in rules)
    total_bytes = sum(r['bytes'] for r in rules)
    
    print()
    print_color("【规则统计】", Colors.YELLOW + Colors.BOLD)
    print(f"  IPv4 转发规则数: {ipv4_count}")
    print(f"  IPv6 转发规则数: {ipv6_count}")
    print(f"  总计: {len(rules)}")
    print(f"  总流量: {format_packets(total_packets)} 包 / {format_bytes(total_bytes)}")
    
    # 域名映射统计
    config = load_domain_config()
    domain_count = len(config.get("mappings", []))
    if domain_count > 0:
        print()
        print_color("【域名映射】", Colors.YELLOW + Colors.BOLD)
        print(f"  域名规则数: {domain_count}")

def show_help():
    """显示帮助信息"""
    print_header("帮助信息")
    
    print_color("【关于端口转发】", Colors.YELLOW + Colors.BOLD)
    print("""
端口转发允许将发送到本机某端口的流量转发到另一个IP地址和端口。
常见用途包括：
  - 将流量转发到内网服务器
  - NAT穿透
  - 负载均衡前端

【使用说明】
  1. 添加单端口转发：将单个端口的流量转发到目标地址
  2. 添加端口范围转发：将连续端口的流量转发到目标地址
  3. 查看规则：以表格形式显示当前配置的所有转发规则
  4. 删除规则：选择编号删除指定规则
  5. 清空规则：删除所有NAT规则（谨慎使用）
  6. 域名服务：管理域名动态解析服务

【域名支持】
  - 目标地址可以输入域名，系统会自动解析为IP
  - 启动守护进程后，每10分钟自动检查域名IP变化
  - IP变化时自动更新转发规则

【默认值】
  - 协议默认选择: TCP + UDP（直接回车即可）
  - 目标端口默认: 与本地端口相同
  - 端口映射默认: 保持原端口

【注意事项】
  - 需要root权限运行
  - 修改后建议保存规则，否则重启后失效
  - IPv6转发需要目标支持IPv6
  - 确保防火墙允许相关端口的流量
""")

def main_menu():
    """主菜单"""
    while True:
        print()
        print_color("=" * 60, Colors.CYAN)
        print_color("             nfter - nftables 端口转发管理工具", Colors.CYAN + Colors.BOLD)
        print_color("一个交互式的 nftables 端口转发管理工具，适用于 Debian/Ubuntu 系统。", Colors.CYAN)
        print_color("特点：① 采用systemd和配置文件对iptables的替代品nftables进行管理", Colors.CYAN)
        print_color("      ② 实现不加密单个端口转发和连续多个端口转发，支持IPv4、IPv6及域名", Colors.CYAN)
        print_color("      ③ 系统级内核转发效率更高", Colors.CYAN)
        print_color("说明文档：https://github.com/Yorkian/Nfter", Colors.CYAN)
        print_color("=" * 60, Colors.CYAN)
        print()
        print("  1. 添加单端口转发")
        print("  2. 添加端口范围转发")
        print("  3. 查看当前规则")
        print("  4. 删除规则")
        print("  5. 清空所有规则")
        print("  6. 保存规则")
        print("  7. 域名监控服务")
        print("  8. 系统状态")
        print("  9. 帮助")
        print("  0. 退出")
        print()
        
        choice = input(f"{Colors.CYAN}请选择操作 [0-9]: {Colors.ENDC}").strip()
        
        if choice == '1':
            add_single_port_forward()
        elif choice == '2':
            add_port_range_forward()
        elif choice == '3':
            show_rules()
        elif choice == '4':
            delete_rule()
        elif choice == '5':
            flush_rules()
        elif choice == '6':
            save_rules()
        elif choice == '7':
            manage_daemon()
        elif choice == '8':
            show_status()
        elif choice == '9':
            show_help()
        elif choice == '0':
            print_info("感谢使用，再见！")
            sys.exit(0)
        else:
            print_error("无效选择，请重试")
        
        input(f"\n{Colors.CYAN}按回车键继续...{Colors.ENDC}")

def main():
    """主函数"""
    # 检查命令行参数
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'daemon':
            # 作为守护进程运行
            check_root()
            daemon_loop()
            return
        elif cmd == 'update':
            # 手动触发更新
            check_root()
            update_domain_ip()
            return
        elif cmd == 'start':
            check_root()
            start_daemon()
            return
        elif cmd == 'stop':
            check_root()
            stop_daemon()
            return
        elif cmd == 'status':
            running, pid = daemon_status()
            if running:
                print(f"守护进程运行中 (PID: {pid})")
            else:
                print("守护进程未运行")
            return
    
    try:
        check_root()
        check_nftables()
        init_nat_table()
        main_menu()
        
    except KeyboardInterrupt:
        print("\n")
        print_info("用户中断，退出程序")
        sys.exit(0)

if __name__ == "__main__":
    main()

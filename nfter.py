#!/usr/bin/env python3
"""
nfter - nftables 端口转发管理工具 (链式转发修复版)
修复了链式转发失效问题：masquerade 规则现在匹配目标 IP
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
ACL_CONFIG_FILE = "/etc/nfter/acl.json"
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
    print(f"{color}{text}{Colors.ENDC}")

def print_header(text):
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
    text = str(text)
    current_width = get_display_width(text)
    padding_needed = target_width - current_width
    if padding_needed <= 0: return text
    if align == 'center':
        left_pad = padding_needed // 2
        right_pad = padding_needed - left_pad
        return ' ' * left_pad + text + ' ' * right_pad
    elif align == 'left': return text + ' ' * padding_needed
    else: return ' ' * padding_needed + text

def format_bytes(bytes_count):
    try: bytes_count = int(bytes_count)
    except: return "0 B"
    if bytes_count < 1024: return f"{bytes_count} B"
    elif bytes_count < 1024 * 1024: return f"{bytes_count / 1024:.1f} KB"
    elif bytes_count < 1024 * 1024 * 1024: return f"{bytes_count / (1024 * 1024):.1f} MB"
    else: return f"{bytes_count / (1024 * 1024 * 1024):.2f} GB"

def format_packets(packets_count):
    try: packets_count = int(packets_count)
    except: return "0"
    if packets_count < 1000: return str(packets_count)
    elif packets_count < 1000000: return f"{packets_count / 1000:.1f}K"
    else: return f"{packets_count / 1000000:.1f}M"

def run_cmd(cmd, capture=True):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=capture, text=True, timeout=30)
        return result.returncode == 0, result.stdout, result.stderr
    except: return False, "", "Timeout"

def check_root():
    if os.getuid() != 0:
        print_error("需要root权限运行！")
        sys.exit(1)

def check_nftables():
    success, _, _ = run_cmd("which nft")
    if not success:
        print_error("nftables 未安装！")
        sys.exit(1)
    run_cmd("systemctl start nftables")
    run_cmd("systemctl enable nftables")

def init_nat_table():
    run_cmd("nft add table ip nat")
    run_cmd("nft add table ip6 nat")
    run_cmd("nft 'add chain ip nat prerouting { type nat hook prerouting priority -100 ; }'")
    run_cmd("nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'")
    run_cmd("nft 'add chain ip6 nat prerouting { type nat hook prerouting priority -100 ; }'")
    run_cmd("nft 'add chain ip6 nat postrouting { type nat hook postrouting priority 100 ; }'")
    run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    run_cmd("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

def init_filter_table():
    """初始化 filter 表和链（用于端口访问限制功能）"""
    for family in ['ip', 'ip6']:
        run_cmd(f"nft add table {family} filter")
        run_cmd(f"nft 'add chain {family} filter input {{ type filter hook input priority 0 ; policy accept ; }}'")
        run_cmd(f"nft 'add chain {family} filter forward {{ type filter hook forward priority 0 ; policy accept ; }}'")

def validate_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return True, ip.version
    except: return False, None

def validate_ip_or_cidr(ip_str):
    """验证 IP 地址或 CIDR 格式"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return True, ip.version
    except:
        pass
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
        return True, net.version
    except:
        return False, None

def validate_target(target_str):
    valid, version = validate_ip(target_str)
    if valid: return True, target_str, version, False
    ip, version = resolve_domain(target_str)
    if ip: return True, ip, version, True
    return False, None, None, False

def validate_port(port_str):
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except: return False

def resolve_domain(domain):
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        if result: return result[0][4][0], 4
    except: pass
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET6)
        if result: return result[0][4][0], 6
    except: pass
    return None, None

def get_input(prompt, validator=None, error_msg="输入无效", default=None):
    while True:
        display_prompt = f"{Colors.CYAN}{prompt} [默认: {default}]: {Colors.ENDC}" if default is not None else f"{Colors.CYAN}{prompt}: {Colors.ENDC}"
        value = input(display_prompt).strip()
        if value.lower() == 'q': return None
        if value == '' and default is not None: return default
        if value == '' and default is None:
            print_error(error_msg)
            continue
        if validator is None or validator(value): return value
        print_error(error_msg)

# ==================== 配置管理 (全量追踪修复版) ====================

def load_domain_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f: return json.load(f)
        except: return {"mappings": []}
    return {"mappings": []}

def save_domain_config(config):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f: json.dump(config, f, indent=2)

def load_acl_config():
    if os.path.exists(ACL_CONFIG_FILE):
        try:
            with open(ACL_CONFIG_FILE, 'r') as f: return json.load(f)
        except: return {"rules": []}
    return {"rules": []}

def save_acl_config(config):
    os.makedirs(os.path.dirname(ACL_CONFIG_FILE), exist_ok=True)
    with open(ACL_CONFIG_FILE, 'w') as f: json.dump(config, f, indent=2)

def add_mapping_record(domain, current_ip, ip_version, local_port, target_port, protocols, dnat_handles, masq_handles):
    config = load_domain_config()
    mapping = {
        "domain": domain, 
        "current_ip": current_ip,
        "ip_version": ip_version,
        "local_port": str(local_port),
        "target_port": str(target_port),
        "protocols": protocols,
        "dnat_handles": dnat_handles,
        "masq_handles": masq_handles,
        "updated_at": datetime.now().isoformat()
    }
    config["mappings"].append(mapping)
    save_domain_config(config)

def remove_mapping_by_handle(handle):
    config = load_domain_config()
    new_mappings = []
    found = False
    for m in config["mappings"]:
        if handle in m.get("dnat_handles", []) or str(handle) == str(m.get("handle")):
            found = True
            table = "ip" if m.get("ip_version") == 4 else "ip6"
            for h in m.get("dnat_handles", [m.get("handle")]):
                if h: run_cmd(f"nft delete rule {table} nat prerouting handle {h} 2>/dev/null")
            for h in m.get("masq_handles", []):
                run_cmd(f"nft delete rule {table} nat postrouting handle {h} 2>/dev/null")
        else:
            new_mappings.append(m)
    if found: save_domain_config({"mappings": new_mappings})
    return found

def update_rule_ip(mapping, new_ip, new_version):
    """域名IP监控更新 - 修复版：masquerade 匹配目标 IP"""
    l_port, t_port, protos = mapping.get("local_port"), mapping.get("target_port"), mapping.get("protocols", [])
    table = "ip" if new_version == 4 else "ip6"
    addr_family = "ip" if new_version == 4 else "ip6"
    
    for h in mapping.get("dnat_handles", [mapping.get("handle")]):
        if h: run_cmd(f"nft delete rule {table} nat prerouting handle {h} 2>/dev/null")
    for h in mapping.get("masq_handles", []):
        run_cmd(f"nft delete rule {table} nat postrouting handle {h} 2>/dev/null")
    
    new_d_hs, new_m_hs = [], []
    p_map = ""
    if '-' in str(l_port) and l_port != t_port:
        ls, le = map(int, l_port.split('-'))
        ts, _ = map(int, t_port.split('-'))
        p_map = "{ " + ", ".join([f"{ls+i} : {ts+i}" for i in range(le-ls+1)]) + " }"
    
    for p in protos:
        if new_version == 4:
            cmd = f"nft add rule {table} nat prerouting {p} dport {l_port} counter dnat to {new_ip}:{t_port}" if not p_map else f"nft add rule {table} nat prerouting {p} dport {l_port} counter dnat to {new_ip} : {p} dport map {p_map}"
        else:
            cmd = f"nft add rule {table} nat prerouting {p} dport {l_port} counter dnat to [{new_ip}]:{t_port}" if not p_map else f"nft add rule {table} nat prerouting {p} dport {l_port} counter dnat to [{new_ip}] : {p} dport map {p_map}"
        
        if run_cmd(cmd)[0]:
            h_out = run_cmd(f"nft -a list chain {table} nat prerouting | grep '{p} dport {l_port}' | grep -oP 'handle \\d+' | tail -1")[1]
            m = re.search(r'handle (\d+)', h_out)
            if m: new_d_hs.append(m.group(1))
        
        m_cmd = f"nft add rule {table} nat postrouting {addr_family} daddr {new_ip} {p} dport {t_port} counter masquerade"
        if run_cmd(m_cmd)[0]:
            mh_out = run_cmd(f"nft -a list chain {table} nat postrouting | grep '{p} dport {t_port}' | grep 'daddr {new_ip}' | grep -oP 'handle \\d+' | tail -1")[1]
            mm = re.search(r'handle (\d+)', mh_out)
            if mm: new_m_hs.append(mm.group(1))
    
    mapping["dnat_handles"], mapping["masq_handles"] = new_d_hs, new_m_hs
    return len(new_d_hs) > 0

def update_domain_ip():
    """域名 IP 监控守护进程的更新函数"""
    config = load_domain_config()
    updated = False
    for m in config.get("mappings", []):
        domain = m.get("domain")
        if not domain or validate_ip(domain)[0]:
            continue
        
        new_ip, new_version = resolve_domain(domain)
        if new_ip and new_ip != m.get("current_ip"):
            log_msg = f"[{datetime.now().isoformat()}] 域名 {domain} IP 变更: {m.get('current_ip')} -> {new_ip}"
            try:
                with open(LOG_FILE, 'a') as f:
                    f.write(log_msg + "\n")
            except:
                pass
            
            if update_rule_ip(m, new_ip, new_version):
                m["current_ip"] = new_ip
                m["ip_version"] = new_version
                m["updated_at"] = datetime.now().isoformat()
                updated = True
    
    if updated:
        save_domain_config(config)
        save_rules()

# ==================== 规则解析 (精确显示修复版) ====================

def parse_forward_rules():
    rules, rid, config = [], 1, load_domain_config()
    handle_meta = {}
    for m in config.get("mappings", []):
        d_hs = m.get("dnat_handles", [m.get("handle")])
        for h in d_hs:
            if h: handle_meta[str(h)] = {"port": m.get("target_port"), "domain": m.get("domain") if not validate_ip(m.get("domain"))[0] else ""}
            
    for v in ['IPv4', 'IPv6']:
        table = "ip" if v == 'IPv4' else "ip6"
        success, stdout, _ = run_cmd(f"nft -a list chain {table} nat prerouting 2>/dev/null")
        if success:
            for line in stdout.split('\n'):
                if 'dnat to' in line:
                    r = parse_single_rule(line, v, rid, handle_meta)
                    if r: rules.append(r); rid += 1
    return rules

def parse_single_rule(line, version, rid, meta):
    r = {'id': rid, 'ip_version': version, 'protocol': 'ALL', 'local_port': '', 'target_ip': '', 'target_port': '', 'handle': '', 'packets': 0, 'bytes': 0, 'domain': ''}
    if 'tcp dport' in line.lower(): r['protocol'] = 'TCP'
    elif 'udp dport' in line.lower(): r['protocol'] = 'UDP'
    
    lp_m = re.search(r'dport\s+(\d+(?:-\d+)?)', line)
    if lp_m: r['local_port'] = lp_m.group(1)
    
    h_m = re.search(r'handle\s+(\d+)', line)
    if h_m: r['handle'] = h_m.group(1)
    
    c_m = re.search(r'packets\s+(\d+)\s+bytes\s+(\d+)', line)
    if c_m: r['packets'], r['bytes'] = int(c_m.group(1)), int(c_m.group(2))

    if r['handle'] in meta:
        r['target_port'] = meta[r['handle']]['port']
        r['domain'] = meta[r['handle']]['domain']
    
    if version == 'IPv4':
        m = re.search(r'dnat to\s+([\d.]+)(?:\s+:\s+\w+\s+dport\s+map\s+\{[^\}]+\}|:(\d+(?:-\d+)?))?', line)
        if m: 
            r['target_ip'] = m.group(1)
            if not r['target_port']: r['target_port'] = m.group(2) if m.group(2) else r['local_port']
    else:
        m = re.search(r'dnat to\s+\[([^\]]+)\](?:\s+:\s+\w+\s+dport\s+map\s+\{[^\}]+\}|:(\d+(?:-\d+)?))?', line)
        if m: 
            r['target_ip'] = m.group(1)
            if not r['target_port']: r['target_port'] = m.group(2) if m.group(2) else r['local_port']
            
    return r if r['local_port'] and r['target_ip'] else None

# ==================== 端口访问限制 (IP 白名单) ====================

def ensure_filter_chain(tables):
    """确保指定 family 的 filter 表和 input 链存在（防御性创建）"""
    for table, _ in tables:
        run_cmd(f"nft add table {table} filter")
        run_cmd(f"nft 'add chain {table} filter input {{ type filter hook input priority 0 ; policy accept ; }}'")

def add_acl_rule():
    """添加端口访问限制规则"""
    print_header("添加端口访问限制 (IP 白名单)")
    print_info("此功能将限制指定端口只允许白名单 IP 访问")
    print()
    
    port = get_input("要限制的端口", validate_port, "1-65535")
    if not port: return
    
    p_choice = get_input("协议 [1.TCP 2.UDP 3.ALL]", lambda x: x in ['1','2','3'], "请输入 1-3", default='3')
    if not p_choice: return
    protos = ['tcp'] if p_choice=='1' else ['udp'] if p_choice=='2' else ['tcp', 'udp']
    
    v_choice = get_input("IP版本 [1.IPv4 2.IPv6 3.ALL]", lambda x: x in ['1','2','3'], "请输入 1-3", default='1')
    if not v_choice: return
    
    print_info("请输入允许访问的 IP 地址（支持 CIDR 格式，如 192.168.1.0/24）")
    print_info("多个 IP 用逗号分隔，输入完成后按回车")
    whitelist_input = get_input("白名单 IP", lambda x: all(validate_ip_or_cidr(ip.strip())[0] for ip in x.split(',')), "IP 格式无效")
    if not whitelist_input: return
    
    whitelist = [ip.strip() for ip in whitelist_input.split(',')]
    
    tables = []
    if v_choice in ['1', '3']: tables.append(('ip', 4))
    if v_choice in ['2', '3']: tables.append(('ip6', 6))
    
    # 确保 filter 表和 input 链存在
    ensure_filter_chain(tables)
    
    handles = []
    config = load_acl_config()
    
    for table, version in tables:
        addr_family = "ip" if version == 4 else "ip6"
        
        version_whitelist = [ip for ip in whitelist if validate_ip_or_cidr(ip)[1] == version]
        if not version_whitelist:
            continue
        
        if len(version_whitelist) == 1:
            ip_set = version_whitelist[0]
        else:
            ip_set = "{ " + ", ".join(version_whitelist) + " }"
        
        for proto in protos:
            allow_cmd = f"nft add rule {table} filter input {proto} dport {port} {addr_family} saddr {ip_set} counter accept"
            success, _, stderr = run_cmd(allow_cmd)
            if success:
                h_out = run_cmd(f"nft -a list chain {table} filter input | grep '{proto} dport {port}' | grep 'accept' | grep -oP 'handle \\d+' | tail -1")[1]
                hm = re.search(r'handle (\d+)', h_out)
                if hm: handles.append({'table': table, 'chain': 'input', 'handle': hm.group(1), 'type': 'allow'})
                print_success(f"允许规则添加成功 ({table}/{proto})")
            else:
                print_error(f"允许规则添加失败: {stderr}")
            
            drop_cmd = f"nft add rule {table} filter input {proto} dport {port} counter drop"
            success, _, stderr = run_cmd(drop_cmd)
            if success:
                h_out = run_cmd(f"nft -a list chain {table} filter input | grep '{proto} dport {port}' | grep 'drop' | grep -oP 'handle \\d+' | tail -1")[1]
                hm = re.search(r'handle (\d+)', h_out)
                if hm: handles.append({'table': table, 'chain': 'input', 'handle': hm.group(1), 'type': 'drop'})
                print_success(f"拒绝规则添加成功 ({table}/{proto})")
            else:
                print_error(f"拒绝规则添加失败: {stderr}")
    
    if handles:
        rule_record = {
            "port": port,
            "protocols": protos,
            "whitelist": whitelist,
            "handles": handles,
            "created_at": datetime.now().isoformat()
        }
        config["rules"].append(rule_record)
        save_acl_config(config)
        print_success("端口访问限制已生效")
    
    save_rules_prompt()

def list_acl_rules():
    """列出所有端口访问限制规则"""
    print_header("端口访问限制列表")
    config = load_acl_config()
    rules = config.get("rules", [])
    
    if not rules:
        print_info("当前没有端口访问限制规则")
        return
    
    headers = ['编号', '端口', '协议', '白名单 IP']
    col_w = [6, 10, 10, 50]
    
    print_color("┌" + "┬".join("─" * w for w in col_w) + "┐", Colors.CYAN)
    print_color("│" + "│".join(pad_to_width(h, col_w[i]) for i, h in enumerate(headers)) + "│", Colors.CYAN + Colors.BOLD)
    print_color("├" + "┼".join("─" * w for w in col_w) + "┤", Colors.CYAN)
    
    for i, r in enumerate(rules, 1):
        proto_str = '/'.join(p.upper() for p in r.get('protocols', []))
        whitelist_str = ', '.join(r.get('whitelist', []))
        if len(whitelist_str) > 48:
            whitelist_str = whitelist_str[:45] + '...'
        print(f"│{pad_to_width(i, col_w[0])}│{pad_to_width(r.get('port', ''), col_w[1])}│{pad_to_width(proto_str, col_w[2])}│{pad_to_width(whitelist_str, col_w[3], 'left')}│")
    
    print_color("└" + "┴".join("─" * w for w in col_w) + "┘", Colors.CYAN)
    print_info(f"共 {len(rules)} 条访问限制规则")

def delete_acl_rule():
    """删除端口访问限制规则"""
    print_header("删除端口访问限制")
    config = load_acl_config()
    rules = config.get("rules", [])
    
    if not rules:
        print_info("当前没有端口访问限制规则")
        return
    
    list_acl_rules()
    
    idx = get_input("要删除的编号", lambda x: x.isdigit() and 1 <= int(x) <= len(rules), f"1-{len(rules)}")
    if not idx: return
    
    rule = rules[int(idx) - 1]
    
    if input(f"{Colors.RED}确认删除端口 {rule.get('port')} 的访问限制？[y/N]: {Colors.ENDC}").lower() != 'y':
        return
    
    for h in rule.get('handles', []):
        table = h.get('table', 'ip')
        chain = h.get('chain', 'input')
        handle = h.get('handle')
        if handle:
            run_cmd(f"nft delete rule {table} filter {chain} handle {handle} 2>/dev/null")
    
    rules.pop(int(idx) - 1)
    save_acl_config(config)
    print_success("访问限制规则已删除")
    save_rules_prompt()

def acl_menu():
    """端口访问限制菜单"""
    while True:
        print_header("端口访问限制 (IP 白名单)")
        print("  1. 添加访问限制")
        print("  2. 查看限制列表")
        print("  3. 删除访问限制")
        print("  0. 返回主菜单")
        print()
        
        c = input(f"{Colors.CYAN}请选择: {Colors.ENDC}").strip()
        
        if c == '1': add_acl_rule()
        elif c == '2': list_acl_rules()
        elif c == '3': delete_acl_rule()
        elif c == '0': return
        
        input(f"\n{Colors.DIM}按回车键继续...{Colors.ENDC}")

# ==================== 核心功能执行 (链式转发修复版) ====================

def add_single_port_forward():
    print_header("添加单端口转发")
    p_choice = get_input("协议 [1.TCP 2.UDP 3.ALL]", lambda x: x in ['1','2','3'], "请输入 1-3", default='3')
    if not p_choice: return
    protos = ['tcp'] if p_choice=='1' else ['udp'] if p_choice=='2' else ['tcp','udp']
    l_port = get_input("本地端口", validate_port, "1-65535")
    if not l_port: return
    target_in = get_input("目标地址 (IP/域名)", lambda x: validate_target(x)[0], "地址无效")
    if not target_in: return
    _, t_ip, v, is_domain = validate_target(target_in)
    t_port = get_input("目标端口", lambda x: x=='' or validate_port(x), "1-65535", default=l_port)
    
    table = "ip" if v == 4 else "ip6"
    addr_family = "ip" if v == 4 else "ip6"
    d_hs, m_hs = [], []
    
    for p in protos:
        if v == 4:
            cmd = f"nft add rule {table} nat prerouting {p} dport {l_port} counter dnat to {t_ip}:{t_port}"
        else:
            cmd = f"nft add rule {table} nat prerouting {p} dport {l_port} counter dnat to [{t_ip}]:{t_port}"
        
        if run_cmd(cmd)[0]:
            h_out = run_cmd(f"nft -a list chain {table} nat prerouting | grep '{p} dport {l_port}' | grep -oP 'handle \\d+' | tail -1")[1]
            dm = re.search(r'handle (\d+)', h_out)
            if dm: d_hs.append(dm.group(1))
        
        m_cmd = f"nft add rule {table} nat postrouting {addr_family} daddr {t_ip} {p} dport {t_port} counter masquerade"
        if run_cmd(m_cmd)[0]:
            mh_out = run_cmd(f"nft -a list chain {table} nat postrouting | grep '{p} dport {t_port}' | grep 'daddr {t_ip}' | grep -oP 'handle \\d+' | tail -1")[1]
            mm = re.search(r'handle (\d+)', mh_out)
            if mm: m_hs.append(mm.group(1))
            
    if d_hs:
        add_mapping_record(target_in, t_ip, v, l_port, t_port, protos, d_hs, m_hs)
        print_success("规则已添加并同步至数据库")
        if is_domain: start_daemon()
    save_rules_prompt()

def add_port_range_forward():
    print_header("添加范围转发 (1:1 映射修复版)")
    p_choice = get_input("协议 [1.TCP 2.UDP 3.ALL]", lambda x: x in ['1','2','3'], "1-3", default='3')
    if not p_choice: return
    protos = ['tcp'] if p_choice=='1' else ['udp'] if p_choice=='2' else ['tcp','udp']
    sp = get_input("起始端口", validate_port, "1-65535")
    ep = get_input("结束端口", lambda x: validate_port(x) and int(x)>=int(sp), f"{sp}-65535")
    if not ep: return
    target_in = get_input("目标地址", lambda x: validate_target(x)[0], "地址无效")
    if not target_in: return
    _, t_ip, v, is_domain = validate_target(target_in)
    tsp = get_input("目标起始端口", validate_port, "1-65535", default=sp)
    
    count = int(ep) - int(sp)
    tep = int(tsp) + count
    entries = [f"{int(sp)+i} : {int(tsp)+i}" for i in range(count + 1)]
    p_map = "{ " + ", ".join(entries) + " }"
    
    table = "ip" if v == 4 else "ip6"
    addr_family = "ip" if v == 4 else "ip6"
    d_hs, m_hs = [], []
    
    for p in protos:
        if sp == tsp:
            if v == 4:
                cmd = f"nft add rule {table} nat prerouting {p} dport {sp}-{ep} counter dnat to {t_ip}"
            else:
                cmd = f"nft add rule {table} nat prerouting {p} dport {sp}-{ep} counter dnat to [{t_ip}]"
        else:
            ip_p = t_ip if v == 4 else f"[{t_ip}]"
            cmd = f"nft add rule {table} nat prerouting {p} dport {sp}-{ep} counter dnat to {ip_p} : {p} dport map {p_map}"
        
        if run_cmd(cmd)[0]:
            h_out = run_cmd(f"nft -a list chain {table} nat prerouting | grep '{p} dport {sp}-{ep}' | grep -oP 'handle \\d+' | tail -1")[1]
            dm = re.search(r'handle (\d+)', h_out)
            if dm: d_hs.append(dm.group(1))
        
        m_cmd = f"nft add rule {table} nat postrouting {addr_family} daddr {t_ip} {p} dport {tsp}-{tep} counter masquerade"
        if run_cmd(m_cmd)[0]:
            mh_out = run_cmd(f"nft -a list chain {table} nat postrouting | grep '{p} dport {tsp}-{tep}' | grep 'daddr {t_ip}' | grep -oP 'handle \\d+' | tail -1")[1]
            mm = re.search(r'handle (\d+)', mh_out)
            if mm: m_hs.append(mm.group(1))

    if d_hs:
        add_mapping_record(target_in, t_ip, v, f"{sp}-{ep}", f"{tsp}-{tep}", protos, d_hs, m_hs)
        print_success("1:1 范围映射已添加")
        if is_domain: start_daemon()
    save_rules_prompt()

def delete_rule():
    """彻底删除 (修复版：确保 IP 转发也能物理清理)"""
    print_header("删除转发规则")
    rules = parse_forward_rules()
    if not rules:
        print_info("当前没有转发规则")
        return
    print_rules_table(rules)
    idx = get_input("编号", lambda x: x.isdigit() and 1<=int(x)<=len(rules), f"1-{len(rules)}")
    if not idx: return
    r = rules[int(idx)-1]
    if input(f"{Colors.RED}确认删除？[y/N]: {Colors.ENDC}").lower() != 'y': return
    
    if not remove_mapping_by_handle(r['handle']):
        table = "ip" if r['ip_version'] == 'IPv4' else "ip6"
        run_cmd(f"nft delete rule {table} nat prerouting handle {r['handle']} 2>/dev/null")
        print_success("DNAT 规则已删除")
    else:
        print_success("已连带清理转发记录及伪装规则")
    save_rules_prompt()

# ==================== 界面展示 ====================

def print_rules_table(rules):
    if not rules:
        print_info("当前没有转发规则")
        return
    headers = ['编号', '协议', '本地端口', '目标地址', '目标端口', '流量', 'IP版本']
    col_w = [6, 6, 15, 20, 15, 18, 8]
    print_color("┌" + "┬".join("─" * w for w in col_w) + "┐", Colors.CYAN)
    print_color("│" + "│".join(pad_to_width(h, col_w[i]) for i, h in enumerate(headers)) + "│", Colors.CYAN + Colors.BOLD)
    print_color("├" + "┼".join("─" * w for w in col_w) + "┤", Colors.CYAN)
    
    total_packets, total_bytes = 0, 0
    for r in rules:
        traffic = f"{format_packets(r['packets'])}包/{format_bytes(r['bytes'])}"
        target = r['domain'] if r['domain'] else r['target_ip']
        total_packets += r['packets']
        total_bytes += r['bytes']
        print(f"│{pad_to_width(r['id'], col_w[0])}│{pad_to_width(r['protocol'], col_w[1])}│{pad_to_width(r['local_port'], col_w[2])}│{pad_to_width(target, col_w[3])}│{pad_to_width(r['target_port'], col_w[4])}│{pad_to_width(traffic, col_w[5])}│{pad_to_width(r['ip_version'], col_w[6])}│")
    
    print_color("└" + "┴".join("─" * w for w in col_w) + "┘", Colors.CYAN)
    print_info(f"共 {len(rules)} 条转发规则 | 总流量: {format_packets(total_packets)} 包 / {format_bytes(total_bytes)}")

def save_rules():
    ok, out, _ = run_cmd("nft list ruleset")
    if ok:
        with open("/etc/nftables.conf", "w") as f:
            f.write("#!/usr/sbin/nft -f\n\nflush ruleset\n\n" + out)
        print_success("已保存至 /etc/nftables.conf")

def save_rules_prompt():
    if input(f"\n{Colors.CYAN}是否保存配置？[Y/n]: {Colors.ENDC}").lower() != 'n': save_rules()

def daemon_status():
    if not os.path.exists(PID_FILE): return False, None
    try:
        with open(PID_FILE, 'r') as f: pid = int(f.read().strip())
        os.kill(pid, 0); return True, pid
    except: return False, None

def start_daemon():
    r, _ = daemon_status()
    if r:
        print_info("域名监控守护进程已在运行")
        return
    pid = os.fork()
    if pid > 0:
        print_success("域名监控守护进程已启动")
        return
    os.setsid()
    if os.fork() > 0: os._exit(0)
    with open(PID_FILE, 'w') as f: f.write(str(os.getpid()))
    while True:
        try: update_domain_ip()
        except: pass
        time.sleep(600)

def stop_daemon():
    running, pid = daemon_status()
    if running and pid:
        try:
            os.kill(pid, signal.SIGTERM)
            os.remove(PID_FILE)
            print_success("守护进程已停止")
        except:
            print_error("停止守护进程失败")
    else:
        print_info("守护进程未在运行")

def show_system_status():
    print_header("系统状态")
    
    _, ipv4_fwd, _ = run_cmd("cat /proc/sys/net/ipv4/ip_forward")
    _, ipv6_fwd, _ = run_cmd("cat /proc/sys/net/ipv6/conf/all/forwarding")
    print(f"  IPv4 转发: {'✓ 已启用' if ipv4_fwd.strip() == '1' else '✗ 未启用'}")
    print(f"  IPv6 转发: {'✓ 已启用' if ipv6_fwd.strip() == '1' else '✗ 未启用'}")
    
    running, pid = daemon_status()
    print(f"  域名监控: {'✓ 运行中 (PID: ' + str(pid) + ')' if running else '✗ 未运行'}")
    
    rules = parse_forward_rules()
    print(f"  转发规则: {len(rules)} 条")
    
    config = load_domain_config()
    domain_count = sum(1 for m in config.get("mappings", []) if not validate_ip(m.get("domain", ""))[0])
    print(f"  域名映射: {domain_count} 个")
    
    acl_config = load_acl_config()
    acl_count = len(acl_config.get("rules", []))
    print(f"  访问限制: {acl_count} 条")

def show_help():
    print_header("使用帮助")
    print("""
  本工具用于管理 nftables 端口转发规则。

  【链式转发说明】
  本版本已修复链式转发问题。masquerade 规则现在会匹配目标 IP，
  确保 A -> B -> C 的多级转发能正常工作。

  【功能说明】
  1. 单端口转发：将本地端口转发到目标 IP:端口
  2. 范围转发：支持 1:1 端口映射，如 2001-2010 -> 3001-3010
  3. 域名支持：目标地址可使用域名，系统会自动解析并监控 IP 变化
  4. 端口访问限制：可设置 IP 白名单，限制端口只允许特定 IP 访问

  【命令行参数】
  nfter daemon    - 以守护进程模式运行（用于域名监控）
  nfter start     - 启动域名监控守护进程
  nfter stop      - 停止守护进程
  nfter status    - 查看系统状态

  【配置文件】
  /etc/nfter/domains.json  - 域名映射配置
  /etc/nfter/acl.json      - 访问限制配置
  /etc/nftables.conf       - nftables 规则配置
  /var/log/nfter.log       - 运行日志
    """)

def main_menu():
    while True:
        print()
        print_color("=" * 60, Colors.CYAN)
        print_color("             nfter - nftables 端口转发管理工具", Colors.CYAN + Colors.BOLD)
        print_color("一个交互式的 nftables 端口转发管理工具，适用于 Debian/Ubuntu 系统。", Colors.CYAN)
        print_color("特点：① 采用systemd和配置文件对iptables的替代品nftables进行管理", Colors.CYAN)
        print_color("      ② 实现不加密单个端口转发和连续多个端口转发，支持IPv4、IPv6及域名", Colors.CYAN)
        print_color("      ③ 系统级内核转发效率更高", Colors.CYAN)
        print_color("      ④ 支持端口访问限制（IP白名单）", Colors.CYAN)
        print_color("说明文档：https://github.com/Yorkian/Nfter", Colors.CYAN)
        print_color("=" * 60, Colors.CYAN)
        print()
        print("  1. 添加单端口转发")
        print("  2. 添加端口范围转发")
        print("  3. 查看当前规则")
        print("  4. 删除单条规则")
        print("  5. 清空所有规则")
        print("  6. 保存规则配置")
        print("  7. 域名监控服务")
        print("  8. 端口访问限制")
        print("  9. 系统状态")
        print("  h. 帮助")
        print("  0. 退出")
        print()
        
        c = input(f"{Colors.CYAN}请选择: {Colors.ENDC}").strip()
        
        if c == '1': add_single_port_forward()
        elif c == '2': add_port_range_forward()
        elif c == '3': print_rules_table(parse_forward_rules())
        elif c == '4': delete_rule()
        elif c == '5':
            if input("输入 'yes' 确认清空: ").lower() == 'yes':
                run_cmd("nft flush table ip nat"); run_cmd("nft flush table ip6 nat")
                save_domain_config({"mappings": []}); init_nat_table(); print_success("已清空")
        elif c == '6': save_rules()
        elif c == '7':
            print("\n  1. 启动监控  2. 停止监控  3. 立即更新域名IP")
            sub = input(f"{Colors.CYAN}  选择: {Colors.ENDC}").strip()
            if sub == '1': start_daemon()
            elif sub == '2': stop_daemon()
            elif sub == '3': update_domain_ip(); print_success("域名IP已更新")
        elif c == '8': acl_menu()
        elif c == '9': show_system_status()
        elif c == 'h' or c == 'H': show_help()
        elif c == '0': sys.exit(0)
        else:
            continue
        
        input(f"\n{Colors.DIM}按回车键继续...{Colors.ENDC}")

if __name__ == "__main__":
    check_root(); check_nftables(); init_nat_table(); init_filter_table()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'daemon': start_daemon()
        elif cmd == 'start': start_daemon()
        elif cmd == 'stop': stop_daemon()
        elif cmd == 'status': show_system_status()
        elif cmd == 'update': update_domain_ip(); print_success("域名IP已更新")
        else: print_error(f"未知命令: {cmd}")
    else:
        try: main_menu()
        except KeyboardInterrupt: print("\n"); sys.exit(0)

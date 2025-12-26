# nfter - nftables 端口转发管理工具

一个交互式的 nftables 端口转发管理工具，适用于 Debian/Ubuntu 系统。

## 功能特性

- ✅ 交互式命令行界面
- ✅ 单端口转发（TCP/UDP）
- ✅ 连续端口范围转发
- ✅ 支持 IPv4 目标地址
- ✅ 支持 IPv6 目标地址
- ✅ **支持域名作为目标地址**
- ✅ **域名IP自动更新（每10分钟检测）**
- ✅ **流量统计显示（包数/字节数）**
- ✅ 查看当前转发规则（表格形式）
- ✅ 删除指定规则
- ✅ 清空所有规则
- ✅ 规则持久化保存
- ✅ 彩色输出界面

## 系统要求

- Debian 10+ / Ubuntu 18.04+
- Python 3.6+
- nftables
- root 权限

## 快速安装

```bash
# 一键安装并运行
curl -fsSL https://raw.githubusercontent.com/Yorkian/Nfter/main/nfter.sh | sudo bash

# 一键安装并运行(中国大陆加速）
curl -fsSL https://ghproxy.cfd/raw.githubusercontent.com/Yorkian/Nfter/main/nfter.sh | sudo bash

# 或下载后运行
wget https://raw.githubusercontent.com/Yorkian/Nfter/main/nfter.sh
sudo bash nfter.sh
```

## 使用方法

### 启动工具

```bash
sudo nfter
# 或
sudo bash nfter.sh
```

### 主菜单

```
============================================================
             nfter - nftables 端口转发管理工具
一个交互式的 nftables 端口转发管理工具，适用于 Debian/Ubuntu 系统。
特点：①采用systemd和配置文件对iptables的替代品nftables进行管理
     ②实现不加密单个端口转发和连续多个端口转发，支持IPv4、IPv6及域名
     ③系统级内核转发效率更高
说明文档：https://github.com/Yorkian/Nfter
============================================================

  1. 添加单端口转发
  2. 添加端口范围转发
  3. 查看当前规则
  4. 删除规则
  5. 清空所有规则
  6. 保存规则
  7. 域名监控服务
  8. 系统状态
  9. 帮助
  0. 退出

请选择操作 [0-9]:
```

### 规则显示效果

```
┌──────┬──────┬───────────────┬───────────────────┬───────────────┬──────────────────┬────────┐
│ 编号  │ 协议 │   本地端口     │     目标地址       │   目标端口     │        流量        │  IP版本 │
├──────┼──────┼───────────────┼───────────────────┼───────────────┼──────────────────┼────────┤
│  1   │ TCP  │ 40000-49999   │ 10.0.1.1          │ 40000-49999   │ 21.4K包/1.3 MB   │  IPv4  │
│  2   │ UDP  │ 40000-49999   │ 110.0.2.2         │ 40000-49999   │ 1.2K包/188.6 KB  │  IPv4  │
│  3   │ TCP  │    61888      │ example.com       │    15888      │ 7.1K包/440.9 KB  │  IPv4  │
│  4   │ UDP  │    61888      │ example.com       │    15888      │ 4.8K包/726.5 KB  │  IPv4  │
└──────┴──────┴───────────────┴───────────────────┴───────────────┴──────────────────┴────────┘

ℹ 共 4 条转发规则 | 总流量: 34.5K 包 / 2.6 MB
```

## 域名支持

### 使用域名作为目标地址

添加规则时，目标地址可以输入域名：

```
目标地址 (IP或域名): example.com
ℹ 域名 example.com 解析为 93.184.216.34
```

### 域名监控服务

当使用域名时，系统会自动保存域名映射关系。启动域名监控服务后，每10分钟自动检查域名IP是否变化，变化时自动更新规则。

**方式一：通过菜单管理**
```
选择: 7 (域名监控服务)
  1. 启动服务
  2. 停止服务
  3. 重启服务
  4. 立即更新域名IP
  5. 查看日志
```

**方式二：通过命令行**
```bash
sudo nfter start    # 启动守护进程
sudo nfter stop     # 停止守护进程
sudo nfter status   # 查看状态
sudo nfter update   # 立即更新域名IP
```

**方式三：使用 systemd（推荐）**
```bash
sudo systemctl start nfter    # 启动服务
sudo systemctl stop nfter     # 停止服务
sudo systemctl enable nfter   # 开机自启
sudo systemctl status nfter   # 查看状态
```

### 配置文件位置

| 文件 | 用途 |
|------|------|
| `/etc/nfter/domains.json` | 域名映射配置 |
| `/var/log/nfter.log` | 运行日志 |
| `/var/run/nfter-daemon.pid` | PID文件 |

## 示例场景

### 1. 单端口转发到 IP

```
选择: 1
协议: [回车] (默认 TCP+UDP)
本地端口: 8080
目标地址: 192.168.1.100
目标端口: [回车] (默认 8080)
```

### 2. 端口范围转发

```
选择: 2
协议: [回车] (默认 TCP+UDP)
起始端口: 10000
结束端口: 10100
目标地址: 10.0.0.50
映射方式: [回车] (默认保持原端口)
```

### 3. 使用域名转发

```
选择: 1
协议: [回车]
本地端口: 443
目标地址: backend.example.com
目标端口: 8443
是否启动域名监控服务？[Y/n]: [回车]
```

## 流量统计

规则查看时会显示每条规则的流量统计：
- **包数量**: 自动转换为 K/M 单位
- **字节数**: 自动转换为 KB/MB/GB 单位

## 卸载程序

如需完全卸载 nfter，请执行以下命令：

```bash
# 1. 停止并禁用服务
sudo systemctl stop nfter
sudo systemctl disable nfter

# 2. 删除程序文件
sudo rm -f /usr/local/bin/nfter
sudo rm -f /etc/systemd/system/nfter.service

# 3. 删除配置和日志（可选）
sudo rm -rf /etc/nfter
sudo rm -f /var/log/nfter.log
sudo rm -f /var/run/nfter-daemon.pid

# 4. 重载 systemd
sudo systemctl daemon-reload

# 5. 清空转发规则（可选，谨慎操作）
sudo nft flush table ip nat
sudo nft flush table ip6 nat
```

## 常用 nft 命令

```bash
# 查看所有规则
sudo nft list ruleset

# 查看 NAT 表（带流量统计）
sudo nft list table ip nat

# 从文件加载规则
sudo nft -f /etc/nftables.conf
```

## 注意事项

1. **权限要求**：必须使用 root 权限运行
2. **规则持久化**：修改后记得保存规则，否则重启后失效
3. **域名监控**：使用域名转发时建议启动监控服务
4. **防火墙配置**：确保防火墙允许转发端口的流量

## 许可证

MIT License

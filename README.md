# Asn-ProxyIP-Scan

从 ASN 拉取 IP 段 → 端口扫描 → Cloudflare 反代节点检测 → 输出可用 CF 节点。

## 使用

一键启动可视化 Web 界面，在浏览器中完成全流程操作：

＊ 安装pathon 环境

＊ 启动web_server.py

浏览器打开 `http://<服务器IP>:8899`，输入 ASN 即可开始扫描。

<img width="1912" height="902" alt="image" src="https://github.com/user-attachments/assets/3228525e-b875-46f4-923d-e0388a3392c4" />


特性：
- 🎛️ 可视化进度（5 步实时跟踪）
- 📊 结果表格（支持筛选/排序）
- 📥 一键下载 CSV
- ⏹ 随时取消任务
- 🌐 响应式暗色主题 UI

## 依赖工具

| 工具 | 用途 | 来源 |
|------|------|------|
| [masscan](https://github.com/robertdavidgraham/masscan) | 高速端口扫描 | `apt install masscan` |
| [prips](https://manpages.debian.org/prips) | CIDR IP 段展开 | `apt install prips` |
| [RIPEStat API](https://stat.ripe.net/) | ASN → CIDR 查询 | 免费公开 API |
| cf-scanner | CF 反代检测 | 内置 Go 源码，自动编译 |
| 精筛 API | 二次验证节点可用性 | 内置 |

## 输出

运行完成后自动输出 CSV 文件，并提供临时下载链接：

```
📥 下载链接 (临时, 按回车关闭):
http://1.2.3.4:8899/output_AS209242_20260616_120000.csv
```

CSV 列：IP地址, 端口, TLS, 数据中心, 地区, 城市, 网络延迟, 下载速度, ASN

> 下载链接自动检测公网出口 IP（ipify + ip.sb 双 API 备用），支持 NAT/Docker 环境。

## Star History ⭐⭐⭐走起

<a href="https://www.star-history.com/?repos=xiamuzhiyi%2FAsn-ProxyIP-Scan&type=timeline&logscale=&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=xiamuzhiyi/Asn-ProxyIP-Scan&type=timeline&theme=dark&logscale&legend=bottom-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=xiamuzhiyi/Asn-ProxyIP-Scan&type=timeline&logscale&legend=bottom-right" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=xiamuzhiyi/Asn-ProxyIP-Scan&type=timeline&logscale&legend=bottom-right" />
 </picture>
</a>

## 特别鸣谢
EzXxY https://github.com/EzXxY/CF-IP 

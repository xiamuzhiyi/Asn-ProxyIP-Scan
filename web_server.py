#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASNIPtest Web UI — 可视化 ASN→CIDR→masscan→CF检测→API精筛 全流程
启动: python3 web_server.py [--port 8899]
"""
import sys, os, subprocess, json, urllib.request, threading, time, io, csv, ipaddress
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit

# ── Paths ──
BASE = Path(__file__).parent.resolve()

# 跨平台 Python 命令检测
PYTHON_CMD = "python" if os.name == "nt" else "python3"

# cf-scanner 二进制，Windows 加 .exe 后缀
CF_SCANNER_NAME = "cf-scanner.exe" if os.name == "nt" else "cf-scanner"
CF_SCANNER = BASE / CF_SCANNER_NAME
CF_SCANNER_SRC = BASE / "cf-scanner-src" / "main.go"
VERIFY_PY = BASE / "verify.py"
API_URL = "https://api.090227.xyz/check"

# ── 自动编译 cf-scanner (如果缺失) ──
def _ensure_cf_scanner():
    if CF_SCANNER.exists() and os.access(str(CF_SCANNER), os.X_OK):
        return True
    if not CF_SCANNER_SRC.exists():
        print(f"  ⚠️ cf-scanner 源码不存在: {CF_SCANNER_SRC}")
        return False
    print(f"  🔧 cf-scanner 未编译，正在自动编译...")
    try:
        subprocess.run(
            ["go", "build", "-o", str(CF_SCANNER), str(CF_SCANNER_SRC)],
            cwd=str(CF_SCANNER_SRC.parent),
            check=True, timeout=120,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        if CF_SCANNER.exists():
            CF_SCANNER.chmod(0o755)
            print(f"  ✅ cf-scanner 编译完成: {CF_SCANNER.name}")
            return True
    except FileNotFoundError:
        print("  ❌ Go 未安装，请先安装: https://go.dev/dl/")
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)
        print(f"  ❌ 编译失败: {err_msg}")
    except Exception as e:
        print(f"  ❌ 编译异常: {e}")
    return False

_ensure_cf_scanner()

# ── Flask App ──
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Global state ──
current_job = {"running": False, "cancel": False, "thread": None}

# ── 扫描配置 (可被前端自定义覆盖) ──
def _load_default_ports():
    """从 ports.txt 读取端口列表，支持范围语法如 1000-50000"""
    pts = BASE / "ports.txt"
    if pts.exists():
        return ",".join(line.strip() for line in open(pts, encoding="utf-8", errors="replace") if line.strip() and not line.startswith("#"))
    return "80,443,1000-50000"

def get_default_config():
    return {
        "ports": _load_default_ports(),
        "masscan_rate": MASSCAN_RATE,
        "cf_concurrency": CF_SCANNER_CONC,
        "api_concurrent": API_CONCURRENT,
        "api_chunk": API_CHUNK,
    }

# ── Hardware detect (cross-platform) ──
def detect_hardware():
    cpu = os.cpu_count() or 4
    try:
        import psutil
        mem_mb = psutil.virtual_memory().available // (1024 * 1024)
    except ImportError:
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if "MemAvailable" in line:
                        mem_mb = int(line.split()[1]) // 1024
                        break
        except:
            mem_mb = 512
    return cpu, mem_mb

CPU_CORES, RAM_MB = detect_hardware()
MASSCAN_RATE = CPU_CORES * 1000
CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
API_CONCURRENT = min(CPU_CORES * 16, 32)
API_CHUNK = 2000 if RAM_MB < 1024 else 5000

# ── Helper: emit log ──
def emit_log(step, msg, progress=None):
    socketio.emit("log", {"step": step, "msg": msg, "progress": progress})

# ── Step 1: ASN → CIDR ──
def fetch_prefixes(asns):
    emit_log("1/5", f"正在从 RIPEStat 拉取 ASN CIDR 数据...", 5)
    cidrs = []
    total_asns = len(asns)
    for idx, asn in enumerate(asns):
        if current_job["cancel"]:
            return None
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ASNIPtest/2.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                count = 0
                for p in data["data"]["prefixes"]:
                    if ":" not in p["prefix"]:
                        cidrs.append(p["prefix"])
                        count += 1
                emit_log("1/5", f"AS{asn} → {count} 个 IPv4 CIDR", 5 + int((idx+1)/total_asns*20))
        except Exception as e:
            emit_log("1/5", f"AS{asn} → 失败: {e}", 5 + int((idx+1)/total_asns*20))

    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    emit_log("1/5", f"共获取 {len(cidrs)} 个 CIDR", 25)
    return cidrs

# ── CIDR → IP 原生回退 (跨平台) ──
def _python_expand_cidr(cidr):
    """用 Python ipaddress 展开单个 CIDR，生成所有 IPv4 地址"""
    network = ipaddress.IPv4Network(cidr, strict=False)
    for ip in network.hosts():
        yield str(ip)
    yield str(network.broadcast_address)

# ── Step 2: CIDR → IP ──
def expand_ips(config=None):
    if current_job["cancel"]:
        return 0
    emit_log("2/5", "正在展开 CIDR 为 IP 列表...", 27)
    ip_file = BASE / "ips.txt"
    total = 0
    cidrs = open(BASE / "cidrs.txt", encoding="utf-8", errors="replace").readlines()
    total_cidrs = len(cidrs)

    # 检测 prips 是否可用，不可用则使用 Python 原生回退
    use_prips = True
    try:
        subprocess.run(["prips", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        use_prips = False
        emit_log("2/5", "prips 未安装，使用 Python 原生 CIDR 展开 (速度较慢但可用)", 28)

    with open(ip_file, "w", encoding="utf-8") as out:
        for idx, cidr_line in enumerate(cidrs):
            if current_job["cancel"]:
                return 0
            cidr = cidr_line.strip()
            if not cidr:
                continue
            try:
                if use_prips:
                    proc = subprocess.Popen(["prips", cidr], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, encoding="utf-8", errors="replace")
                    for ip in proc.stdout:
                        if current_job["cancel"]:
                            proc.terminate()
                            break
                        out.write(ip)
                        total += 1
                    proc.wait()
                else:
                    # Python 原生：批量写入提升 I/O 性能
                    batch = []
                    for ip in _python_expand_cidr(cidr):
                        if current_job["cancel"]:
                            break
                        batch.append(ip + "\n")
                        total += 1
                        if len(batch) >= 10000:
                            out.write("".join(batch))
                            batch.clear()
                    if batch:
                        out.write("".join(batch))
            except Exception as e:
                emit_log("2/5", f"展开 {cidr} 失败: {e}", 27)
            if idx % max(1, total_cidrs // 10) == 0:
                progress = 27 + int((idx / max(1, total_cidrs)) * 18)
                emit_log("2/5", f"已展开 {total:,} 个 IP...", progress)
    emit_log("2/5", f"共展开 {total:,} 个 IP → 已保存: {ip_file.name}", 45)
    socketio.emit("ip_file", {"count": total, "file": str(ip_file.name), "path": str(ip_file)})
    return total

# ── Step 3: masscan 端口扫描 ──
def run_masscan(config=None):
    if config is None:
        config = get_default_config()
    if current_job["cancel"]:
        return 0

    ports = config.get("ports", _load_default_ports())
    rate = int(config.get("masscan_rate", MASSCAN_RATE))
    emit_log("3/5", f"正在启动 masscan (端口: {ports}, 速率: {rate} pps)...", 47)

    raw_file = BASE / "masscan_raw.txt"      # 原始 masscan -oL 输出
    result_file = BASE / "masscan_result.txt" # 解析后 IP:port 列表
    ip_file = BASE / "ips.txt"
    if not ip_file.exists() or ip_file.stat().st_size == 0:
        emit_log("3/5", "❌ 无 IP 列表", 47)
        return 0

    try:
        sudo = [] if os.name == "nt" else ([] if os.geteuid() == 0 else ["sudo"])
        cmd = sudo + [
            "masscan", "-iL", str(ip_file),
            "-p", ports,
            "--rate", str(rate),
            "-oL", str(raw_file),
            "--wait", "5"
        ]
        emit_log("3/5", f"执行: masscan -iL ips.txt -p {ports} --rate {rate}", 49)

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8", errors="replace")
        for line in proc.stdout:
            if current_job["cancel"]:
                proc.terminate()
                break
            line = line.strip()
            if "rate:" in line or "done" in line.lower() or "%" in line:
                emit_log("3/5", f"masscan: {line}", 50)
        proc.wait()

        if current_job["cancel"]:
            return 0
    except FileNotFoundError:
        emit_log("3/5", "❌ masscan 未安装，请先安装: apt install masscan", 47)
        return 0

    # 解析原始输出 → IP:port 列表
    lines = []
    with open(raw_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] == "open":
                lines.append(f"{parts[3]}:{parts[2]}")

    result_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    emit_log("3/5", f"开放端口: {len(lines)} 个", 59)
    emit_log("3/5", f"原始输出: {raw_file.name} | IP:port: {result_file.name}", 59)
    socketio.emit("masscan_file", {
        "count": len(lines),
        "raw_file": str(raw_file.name),
        "result_file": str(result_file.name)
    })
    return len(lines)

# ── Step 4: cf-scanner 粗筛 ──
def cf_scan(config=None):
    if config is None:
        config = get_default_config()
    if current_job["cancel"]:
        return 0

    concurrency = int(config.get("cf_concurrency", CF_SCANNER_CONC))
    emit_log("4/5", f"正在启动 cf-scanner 检测 Cloudflare 节点 (并发: {concurrency})...", 61)

    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"

    if not new_file.exists() or new_file.stat().st_size == 0:
        emit_log("4/5", "无开放端口，跳过", 61)
        return 0

    if not CF_SCANNER.exists():
        emit_log("4/5", f"❌ cf-scanner 不存在，已尝试自动编译。请手动运行: cd cf-scanner-src && go build -o ../{CF_SCANNER_NAME} main.go", 61)
        return 0

    if not os.access(str(CF_SCANNER), os.X_OK):
        os.chmod(str(CF_SCANNER), 0o755)

    try:
        proc = subprocess.Popen(
            [str(CF_SCANNER), "-i", str(new_file), "-o", str(hits_file), "-c", str(concurrency)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8", errors="replace"
        )
        for line in proc.stdout:
            if current_job["cancel"]:
                proc.terminate()
                break
            line = line.strip()
            if "%" in line or "Scanned" in line:
                progress_match = None
                if "%" in line and "/" in line:
                    try:
                        parts = line.split("/")
                        done_part = parts[0].split()[-1] if parts else "0"
                        total_part = parts[1].split()[0] if len(parts) > 1 else "100"
                        pct = min(99, float(done_part) / max(1, float(total_part)) * 100)
                        progress = 61 + int(pct * 0.18)
                        emit_log("4/5", f"cf-scanner: {line}", progress)
                        progress_match = True
                    except:
                        pass
                if not progress_match:
                    emit_log("4/5", f"cf-scanner: {line}", 65)
        proc.wait()
    except Exception as e:
        emit_log("4/5", f"❌ cf-scanner 执行失败: {e}", 65)
        return 0

    hits = 0
    if hits_file.exists():
        hits = sum(1 for _ in open(hits_file, encoding="utf-8", errors="replace"))
    emit_log("4/5", f"CF 节点命中: {hits} 个", 79)
    return hits

# ── Step 5: API 精筛 ──
def api_verify(config=None):
    if config is None:
        config = get_default_config()
    if current_job["cancel"]:
        return 0

    api_concurrent = int(config.get("api_concurrent", API_CONCURRENT))
    api_chunk = int(config.get("api_chunk", API_CHUNK))
    emit_log("5/5", f"正在调用 API 精筛节点可用性 (并发: {api_concurrent}, 分片: {api_chunk})...", 81)

    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"

    if not hits_file.exists() or hits_file.stat().st_size == 0:
        emit_log("5/5", "无 CF 节点，跳过", 81)
        return 0

    try:
        proc = subprocess.Popen(
            [PYTHON_CMD, str(VERIFY_PY),
             "--input", str(hits_file),
             "--output", str(verified_file),
             "--api", API_URL,
             "--chunk", str(api_chunk),
             "--concurrent", str(api_concurrent)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8", errors="replace"
        )
        for line in proc.stdout:
            if current_job["cancel"]:
                proc.terminate()
                break
            line = line.strip()
            if "/" in line and "通过" in line:
                try:
                    parts = line.split("/")
                    done = int(parts[0].strip())
                    total = int(parts[0].split()[0]) if parts else 1
                    pct = min(99, done / max(1, total) * 100)
                    progress = 81 + int(pct * 0.18)
                    emit_log("5/5", line, progress)
                except:
                    emit_log("5/5", line, 85)
            else:
                emit_log("5/5", line, 85)
        proc.wait()
    except Exception as e:
        emit_log("5/5", f"❌ API 精筛失败: {e}", 85)
        return 0

    passed = 0
    if verified_file.exists():
        passed = sum(1 for _ in open(verified_file, encoding="utf-8", errors="replace"))
    emit_log("5/5", f"精筛通过: {passed} 个", 99)
    return passed

# ── Results ──
def get_results():
    verified_file = BASE / "verified.txt"
    results = []
    if verified_file.exists():
        with open(verified_file, encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if len(row) >= 8:
                    results.append({
                        "ip": row[0].strip(),
                        "port": row[1].strip(),
                        "tls": row[2].strip(),
                        "colo": row[3].strip(),
                        "country": row[4].strip(),
                        "region": row[5].strip(),
                        "latency": row[6].strip(),
                        "speed": row[7].strip(),
                        "asn": row[8].strip() if len(row) > 8 else "",
                    })
    return results

# ── Pipeline runner ──
def run_pipeline(asns, config=None):
    global current_job
    if config is None:
        config = get_default_config()
    current_job["running"] = True
    current_job["cancel"] = False
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        ports_info = config.get("ports", "")
        rate_info = config.get("masscan_rate", MASSCAN_RATE)
        emit_log("start", f"开始扫描 ASN: {', '.join(f'AS{a}' for a in asns)} | 端口: {ports_info} | 速率: {rate_info}pps", 0)
        socketio.emit("status", {"status": "running", "asns": asns, "config": config})

        # Step 1
        cidrs = fetch_prefixes(asns)
        if current_job["cancel"]: return

        # Step 2
        ip_count = expand_ips(config)
        if current_job["cancel"] or ip_count == 0: return

        # Step 3
        open_ports = run_masscan(config)
        if current_job["cancel"]: return

        # Step 4
        cf_hits = cf_scan(config)
        if current_job["cancel"]: return

        # Step 5
        verified = api_verify(config)
        if current_job["cancel"]: return

        # Output CSV
        verified_file = BASE / "verified.txt"
        asn_tag = "_".join(asns)
        output_file = BASE / f"output_{asn_tag}_{ts}.csv"

        if verified_file.exists() and verified_file.stat().st_size > 0:
            lines_out = []
            with open(verified_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("IP地址"):
                        continue
                    if line.count(",") >= 8:
                        lines_out.append(line)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
                for line in lines_out:
                    f.write(line + "\n")

            emit_log("done", f"✅ 完成！共 {len(lines_out)} 条 CF 可用节点", 100)
            socketio.emit("status", {"status": "done", "count": len(lines_out), "file": output_file.name, "asn_tag": asn_tag})
        else:
            emit_log("done", "⚠️ 未找到可用 CF 节点", 100)
            socketio.emit("status", {"status": "done", "count": 0, "file": "", "asn_tag": asn_tag})

    except Exception as e:
        emit_log("error", f"❌ 流水线异常: {e}", 50)
        socketio.emit("status", {"status": "error", "msg": str(e)})
    finally:
        current_job["running"] = False

# ── Routes ──
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def api_status():
    cfg = get_default_config()
    return jsonify({
        "running": current_job["running"],
        "cpu": CPU_CORES,
        "ram": RAM_MB,
        "default_config": cfg,
    })

@app.route("/api/results")
def api_results():
    return jsonify(get_results())

@app.route("/api/download/ips")
def api_download_ips():
    ip_file = BASE / "ips.txt"
    if ip_file.exists():
        return send_file(str(ip_file), mimetype="text/plain", as_attachment=True, download_name="ips.txt")
    return jsonify({"error": "IP 文件不存在"}), 404

@app.route("/api/download/masscan/raw")
def api_download_masscan_raw():
    raw_file = BASE / "masscan_raw.txt"
    if raw_file.exists():
        return send_file(str(raw_file), mimetype="text/plain", as_attachment=True, download_name="masscan_raw.txt")
    return jsonify({"error": "masscan 原始输出不存在"}), 404

@app.route("/api/download/masscan/result")
def api_download_masscan_result():
    result_file = BASE / "masscan_result.txt"
    if result_file.exists():
        return send_file(str(result_file), mimetype="text/plain", as_attachment=True, download_name="masscan_result.txt")
    return jsonify({"error": "masscan 解析结果不存在"}), 404

@app.route("/api/download/<asn_tag>")
def api_download(asn_tag):
    files = sorted(BASE.glob(f"output_{asn_tag}_*.csv"), reverse=True)
    if not files:
        # fallback: try verified.txt
        vf = BASE / "verified.txt"
        if vf.exists():
            return send_file(str(vf), mimetype="text/csv", as_attachment=True, download_name="results.csv")
        return jsonify({"error": "文件不存在"}), 404
    return send_file(str(files[0]), mimetype="text/csv", as_attachment=True, download_name=files[0].name)

@app.route("/api/cancel", methods=["POST"])
def api_cancel():
    current_job["cancel"] = True
    emit_log("cancel", "⚠️ 用户取消扫描", 0)
    return jsonify({"ok": True})

@socketio.on("start_scan")
def handle_start_scan(data):
    if current_job["running"]:
        emit("status", {"status": "busy", "msg": "已有扫描任务在进行中"})
        return

    raw = data.get("asns", "")
    if not raw:
        emit("status", {"status": "error", "msg": "请输入 ASN 编号"})
        return

    asns = [a.strip().replace("AS", "").replace("as", "") for a in raw.replace("，", ",").split(",") if a.strip()]
    if not asns:
        emit("status", {"status": "error", "msg": "ASN 格式不正确"})
        return

    # 解析自定义参数
    config = get_default_config()
    if data.get("ports"):
        config["ports"] = data["ports"].strip()
    if data.get("masscan_rate"):
        try:
            config["masscan_rate"] = int(data["masscan_rate"])
        except ValueError:
            pass
    if data.get("cf_concurrency"):
        try:
            config["cf_concurrency"] = int(data["cf_concurrency"])
        except ValueError:
            pass
    if data.get("api_concurrent"):
        try:
            config["api_concurrent"] = int(data["api_concurrent"])
        except ValueError:
            pass
    if data.get("api_chunk"):
        try:
            config["api_chunk"] = int(data["api_chunk"])
        except ValueError:
            pass

    thread = threading.Thread(target=run_pipeline, args=(asns, config), daemon=True)
    current_job["thread"] = thread
    thread.start()

@socketio.on("connect")
def handle_connect():
    emit("status", {
        "status": "running" if current_job["running"] else "idle",
        "cpu": CPU_CORES,
        "ram": RAM_MB
    })

# ── Main ──
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ASNIPtest Web UI Server")
    parser.add_argument("--port", type=int, default=8899, help="Web server port (default: 8899)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind address")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()

    print(f"""
  ╔══════════════════════════════════════════╗
  ║       ASNIPtest Web UI v2.0             ║
  ║  可视化 ASN → masscan → CF 节点扫描     ║
  ╚══════════════════════════════════════════╝

  硬件: {CPU_CORES}核 {RAM_MB}MB | masscan {MASSCAN_RATE}pps | cf并发 {CF_SCANNER_CONC}c
  Web UI: http://{args.host}:{args.port}
  """)

    socketio.run(app, host=args.host, port=args.port, debug=args.debug, allow_unsafe_werkzeug=True)

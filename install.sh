#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────
# ASNIPtest 一键安装 / 更新 / 卸载
#   curl -fsSL <raw_url> | bash                  # 一键安装
#   bash install.sh                              # 菜单选择
#   bash install.sh update / uninstall           # 直接执行
# ──────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
BOLD='\033[1m'

VERSION="v1.0.8"

logo() {
    echo -e "${CYAN}${BOLD}"
    echo "   ╔══════════════════════════════╗"
    echo "   ║       ASNIPtest  ${VERSION}        ║"
    echo "   ║  ASN → masscan → CF 节点    ║"
    echo "   ╚══════════════════════════════╝"
    echo -e "${NC}"
}

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${RED}[!]${NC} $*"; }

PROJECT_DIR="$HOME/ASNIPtest"
REPO_URL="https://github.com/e13815332/ASNIPtest.git"

# ── 卸载 ──
do_uninstall() {
    echo ""
    for d in "$PROJECT_DIR" "$HOME/cf-ip-scanner.tmp"; do
        if [ -d "$d" ]; then
            rm -rf "$d"
            info "已删除 $d"
        fi
    done
    echo ""
    echo -e "${GREEN}✅ 卸载完成${NC}"
}

# ── 更新 ──
do_update() {
    if [ ! -d "$PROJECT_DIR/.git" ]; then
        warn "项目未安装，请先安装"
        return 1
    fi
    OLD_VER=$(cat "$PROJECT_DIR/VERSION" 2>/dev/null || echo "未知")
    info "当前版本: $OLD_VER → 检查更新..."
    cd "$PROJECT_DIR"
    git pull origin main --ff-only
    NEW_VER=$(cat "$PROJECT_DIR/VERSION" 2>/dev/null || echo "未知")
    if [ "$OLD_VER" = "$NEW_VER" ]; then
        info "已是最新版本 $NEW_VER"
    else
        info "${YELLOW}$OLD_VER → $NEW_VER${NC} 已更新"
        info "重新编译 cf-scanner..."
        rm -rf "$PROJECT_DIR/cf-scanner"    # 清除旧源码目录
        cd "$PROJECT_DIR/cf-scanner-src"
        if grep -q avx2 /proc/cpuinfo 2>/dev/null; then GOAMD=""; else GOAMD="GOAMD64=v2"; fi
        env $GOAMD go build -o "$PROJECT_DIR/cf-scanner" main.go
        chmod +x "$PROJECT_DIR/cf-scanner"
    fi
    echo ""
    echo -e "${GREEN}✅ 版本 $NEW_VER${NC}"
}

# ── 安装 ──
do_install() {
    logo

    if [ "$(uname -s)" != "Linux" ]; then
        warn "当前仅支持 Linux"
        exit 1
    fi
    [ "$(id -u)" = "0" ] && SUDO="" || SUDO="sudo"

    # 清理旧版本临时目录
    for d in "$HOME/cf-ip-scanner.tmp" "$PROJECT_DIR.tmp"; do
        if [ -d "$d" ]; then
            warn "清理旧缓存: $d"
            rm -rf "$d"
        fi
    done

    # 系统依赖
    info "检查系统依赖..."
    install_pkg() {
        local pkg=$1
        if command -v "$pkg" &>/dev/null || dpkg -l "$pkg" &>/dev/null 2>&1 || rpm -q "$pkg" &>/dev/null 2>&1; then
            return 0
        fi
        warn "安装 $pkg ..."
        if command -v apt &>/dev/null; then
            $SUDO apt update -qq && $SUDO apt install -y -qq "$pkg"
        elif command -v yum &>/dev/null; then
            $SUDO yum install -y -q "$pkg"
        elif command -v dnf &>/dev/null; then
            $SUDO dnf install -y -q "$pkg"
        else
            warn "未检测到包管理器，请手动安装: $pkg"
        fi
    }
    install_pkg masscan
    install_pkg libpcap-dev
    install_pkg prips
    install_pkg python3
    install_pkg git

    # Go
    info "检查 Go..."
    if command -v go &>/dev/null; then
        GO_VERSION=$(go version | grep -oP 'go\K[0-9.]+')
        info "Go $GO_VERSION 已安装"
    else
        GO_VER="1.22.2"
        GO_ARCH="linux-amd64"
        warn "安装 Go $GO_VER ..."
        curl -fsSL "https://go.dev/dl/go${GO_VER}.${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
        $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        export PATH="/usr/local/go/bin:$PATH"
        info "Go $GO_VER 安装完成"
    fi

    # 克隆
    if [ -d "$PROJECT_DIR/.git" ]; then
        # 验证是否合法安装
        if [ -f "$PROJECT_DIR/VERSION" ] && [ -f "$PROJECT_DIR/run.py" ]; then
            info "项目已存在 ($(cat "$PROJECT_DIR/VERSION"))，更新中..."
            cd "$PROJECT_DIR"
            git pull origin main --ff-only
        else
            warn "检测到旧版/损坏安装，重新安装..."
            rm -rf "$PROJECT_DIR"
            git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
        fi
    elif [ -d "$PROJECT_DIR" ]; then
        warn "检测到旧版残留，清理..."
        rm -rf "$PROJECT_DIR"
        info "克隆项目..."
        git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
    else
        info "克隆项目..."
        git clone --depth 1 --branch main "$REPO_URL" "$PROJECT_DIR"
    fi

    # 编译
    info "编译 cf-scanner..."
    rm -rf "$PROJECT_DIR/cf-scanner"    # 清除旧源码目录
    cd "$PROJECT_DIR/cf-scanner-src"
    if grep -q avx2 /proc/cpuinfo 2>/dev/null; then GOAMD=""; else GOAMD="GOAMD64=v2"; fi
    env $GOAMD go build -o "$PROJECT_DIR/cf-scanner" main.go
    chmod +x "$PROJECT_DIR/cf-scanner"
    info "cf-scanner 编译完成"

    echo ""
    echo -e "${GREEN}${BOLD}✅ 安装完成，开始运行${NC}"
    echo ""
    exec python3 "$PROJECT_DIR/run.py"
}

# ── 菜单 (交互终端时) ──
show_menu() {
    logo
    echo "  请选择:"
    echo "    ${CYAN}1${NC}) 安装 / 更新"
    echo "    ${CYAN}2${NC}) 仅更新"
    echo "    ${CYAN}3${NC}) 卸载"
    echo ""
    read -p "  输入 [1-3]: " choice
    case "$choice" in
        1) do_install ;;
        2) do_update || exit 1 ;;
        3) do_uninstall ;;
        *) warn "无效选择" ; exit 1 ;;
    esac
}

# ── Main ──
ACTION="${1:-}"

if [ -n "$ACTION" ]; then
    # 明确传参：直接执行
    case "$ACTION" in
        install)   do_install ;;
        update)    do_update || exit 1 ;;
        uninstall) do_uninstall ;;
        *)         warn "未知操作: $ACTION (支持: install / update / uninstall)" ; exit 1 ;;
    esac
elif [ -t 0 ]; then
    # 交互终端：弹菜单
    show_menu
else
    # 管道 (curl|bash)：默认安装
    do_install
fi

#!/usr/bin/env bash
# ASNIPtest 一键卸载
# curl -fsSL https://raw.githubusercontent.com/e13815332/ASNIPtest/main/uninstall.sh | bash

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
info() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${RED}[!]${NC} $*"; }

for d in "$HOME/ASNIPtest" "$HOME/cf-ip-scanner.tmp"; do
    if [ -d "$d" ]; then
        rm -rf "$d"
        info "已删除 $d"
    fi
done

echo ""
echo -e "${GREEN}✅ 卸载完成${NC}"

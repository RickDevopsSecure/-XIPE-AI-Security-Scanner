#!/usr/bin/env bash
# XIPE — Self-updater
# Usage: bash update.sh

set -e

BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
RESET="\033[0m"

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  XIPE — Actualizador v$(cat VERSION 2>/dev/null || echo '?')${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# 1. Pull latest code
echo -e "\n${CYAN}[1/3] Jalando últimos cambios...${RESET}"
git pull --ff-only

NEW_VERSION=$(cat VERSION 2>/dev/null || echo '?')
echo -e "${GREEN}✓ Versión actualizada: $NEW_VERSION${RESET}"

# 2. Update dependencies
echo -e "\n${CYAN}[2/3] Actualizando dependencias...${RESET}"
if [ -d "venv" ]; then
    source venv/bin/activate
    pip install -q --upgrade -r requirements.txt
    echo -e "${GREEN}✓ Dependencias actualizadas${RESET}"
else
    echo "  Sin venv activo — corriendo pip directo"
    pip install -q --upgrade -r requirements.txt
    echo -e "${GREEN}✓ Dependencias actualizadas${RESET}"
fi

# 3. Verify
echo -e "\n${CYAN}[3/3] Verificando instalación...${RESET}"
python main.py --version

echo -e "\n${GREEN}${BOLD}✅ XIPE actualizado a v$NEW_VERSION${RESET}"
echo -e "   Corre: ${CYAN}python main.py --config config.yaml${RESET}\n"

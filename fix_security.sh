#!/bin/bash
# Интерактивный скрипт для настройки безопасности сервера
# Версия 2.0 — исправлены проблемы с Docker и FORWARD chain

set -euo pipefail

# Цветовые коды
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
ORANGE='\033[38;5;208m'
NC='\033[0m' # No Color

# Функции для цветного вывода
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}⚠️${NC}  $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
header() { echo -e "${CYAN}$1${NC}"; }

# Директория для резервных копий
BACKUP_DIR="/root/backups"

# ============================================================================
# ФУНКЦИЯ ВОССТАНОВЛЕНИЯ ИЗ БЭКАПА
# ============================================================================

show_restore_menu() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ВОССТАНОВЛЕНИЕ ИЗ РЕЗЕРВНОЙ КОПИИ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ ! -d "$BACKUP_DIR" ]; then
        error "Директория резервных копий не найдена: $BACKUP_DIR"
        exit 1
    fi
    
    # Ищем бэкапы
    local iptables_backups=($(ls -t "$BACKUP_DIR"/iptables_backup_*.rules 2>/dev/null || true))
    local ssh_backups=($(ls -t "$BACKUP_DIR"/sshd_config.backup.* 2>/dev/null || true))
    local fail2ban_backups=($(ls -t "$BACKUP_DIR"/fail2ban_jail.local.backup.* 2>/dev/null || true))
    
    if [ ${#iptables_backups[@]} -eq 0 ] && [ ${#ssh_backups[@]} -eq 0 ] && [ ${#fail2ban_backups[@]} -eq 0 ]; then
        error "Резервные копии не найдены"
        exit 1
    fi
    
    echo "Доступные резервные копии:"
    echo ""
    
    local restore_options=()
    local option_num=1
    
    if [ ${#iptables_backups[@]} -gt 0 ]; then
        echo -e "${CYAN}iptables:${NC}"
        for backup in "${iptables_backups[@]:0:3}"; do
            local timestamp=$(basename "$backup" | grep -oE '[0-9]{8}_[0-9]{6}')
            echo "  $option_num) $timestamp"
            restore_options+=("iptables:$backup")
            ((option_num++))
        done
        echo ""
    fi
    
    if [ ${#ssh_backups[@]} -gt 0 ]; then
        echo -e "${CYAN}SSH конфигурация:${NC}"
        for backup in "${ssh_backups[@]:0:3}"; do
            local timestamp=$(basename "$backup" | grep -oE '[0-9]{8}_[0-9]{6}')
            echo "  $option_num) $timestamp"
            restore_options+=("ssh:$backup")
            ((option_num++))
        done
        echo ""
    fi
    
    if [ ${#fail2ban_backups[@]} -gt 0 ]; then
        echo -e "${CYAN}fail2ban:${NC}"
        for backup in "${fail2ban_backups[@]:0:3}"; do
            local timestamp=$(basename "$backup" | grep -oE '[0-9]{8}_[0-9]{6}')
            echo "  $option_num) $timestamp"
            restore_options+=("fail2ban:$backup")
            ((option_num++))
        done
        echo ""
    fi
    
    echo "  0) Отмена"
    echo ""
    
    local choice
    while true; do
        echo -ne "${YELLOW}Выберите резервную копию для восстановления (0-$((option_num-1))): ${NC}"
        read -r choice
        
        if [ "$choice" = "0" ]; then
            info "Отменено"
            exit 0
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -lt "$option_num" ]; then
            break
        fi
        echo -e "${RED}Неверный выбор${NC}"
    done
    
    local selected="${restore_options[$((choice-1))]}"
    local type="${selected%%:*}"
    local file="${selected#*:}"
    
    echo ""
    warning "Будет восстановлено: $file"
    
    if ! ask_yes_no "Продолжить? (y/n): " "n"; then
        info "Отменено"
        exit 0
    fi
    
    case "$type" in
        iptables)
            iptables-restore < "$file"
            # Сохраняем восстановленные правила
            if [ -d /etc/iptables ]; then
                iptables-save > /etc/iptables/rules.v4
            fi
            success "iptables восстановлен из $file"
            ;;
        ssh)
            cp "$file" /etc/ssh/sshd_config
            systemctl restart sshd
            success "SSH конфигурация восстановлена из $file"
            ;;
        fail2ban)
            cp "$file" /etc/fail2ban/jail.local
            systemctl restart fail2ban
            success "fail2ban восстановлен из $file"
            ;;
    esac
    
    exit 0
}

# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

# Функция для определения сервиса на порту
get_service_on_port() {
    local port=$1
    local service_name=""
    
    # Получаем PID процесса на порту
    local pid=$(ss -tulpn 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+' | head -1)
    
    if [ -z "$pid" ]; then
        pid=$(lsof -ti:$port 2>/dev/null | head -1)
    fi
    
    if [ -z "$pid" ]; then
        echo ""
        return
    fi
    
    # Пытаемся найти systemd сервис через cgroup
    if [ -f /proc/$pid/cgroup ]; then
        local cgroup_path=$(grep "name=systemd" /proc/$pid/cgroup 2>/dev/null | cut -d: -f3)
        
        if [ -n "$cgroup_path" ]; then
            local unit_name=$(echo "$cgroup_path" | grep -oE '[^/]+\.service$' | head -1)
            
            if [ -n "$unit_name" ] && systemctl is-active --quiet "${unit_name}" 2>/dev/null; then
                service_name="${unit_name%.service}"
                echo "$service_name"
                return
            fi
        fi
    fi
    
    # Проверяем через MainPID всех сервисов
    local found_service=""
    while IFS= read -r unit; do
        local main_pid=$(systemctl show "$unit" --property=MainPID --value 2>/dev/null)
        if [ "$main_pid" = "$pid" ]; then
            found_service="${unit%.service}"
            break
        fi
    done < <(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | \
        awk '{print $1}' | grep -E '\.service$')
    
    if [ -n "$found_service" ]; then
        echo "$found_service"
        return
    fi
    
    # Если не нашли через systemd, берем имя процесса
    local process_name=$(ps -p "$pid" -o comm= 2>/dev/null | head -1)
    if [ -n "$process_name" ]; then
        echo "$process_name"
    else
        echo ""
    fi
}

# Функция для получения описания порта
get_port_description() {
    local port=$1
    case $port in
        22) echo "SSH" ;;
        80) echo "HTTP" ;;
        443) echo "HTTPS" ;;
        53) echo "DNS" ;;
        5432) echo "PostgreSQL" ;;
        3306) echo "MySQL" ;;
        6379) echo "Redis" ;;
        27017) echo "MongoDB" ;;
        *) echo "" ;;
    esac
}

# Функция для получения списка открытых портов (только на внешних интерфейсах)
get_open_ports() {
    # Исключаем порты, слушающие только на localhost (127.0.0.1, ::1)
    ss -tuln 2>/dev/null | grep LISTEN | \
        grep -v '127.0.0.1:' | grep -v '127.0.0.53:' | grep -v '\[::1\]:' | \
        awk '{print $5}' | awk -F: '{print $NF}' | sort -un | grep -E '^[0-9]+$'
}

# Функция для интерактивного вопроса
ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local answer
    
    while true; do
        echo -ne "${YELLOW}$prompt${NC}"
        read -r answer
        answer=${answer:-$default}
        case $answer in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) echo -e "${RED}Пожалуйста, введите y или n${NC}" ;;
        esac
    done
}

# Функция для выбора из меню (поддерживает числа > 9)
ask_menu() {
    local prompt="$1"
    local max=$2
    local choice
    
    while true; do
        echo -ne "${YELLOW}$prompt${NC}"
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$max" ]; then
            echo "$choice"
            return
        else
            echo -e "${RED}Пожалуйста, введите число от 1 до $max${NC}"
        fi
    done
}

# Проверка наличия SSH-ключей для root
check_ssh_keys() {
    local has_keys=false
    
    # Проверяем authorized_keys для root
    if [ -f /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
        local key_count=$(grep -cE '^(ssh-|ecdsa-|sk-)' /root/.ssh/authorized_keys 2>/dev/null || echo 0)
        if [ "$key_count" -gt 0 ]; then
            has_keys=true
        fi
    fi
    
    if [ "$has_keys" = true ]; then
        return 0
    else
        return 1
    fi
}

# Проверка активности Docker
is_docker_active() {
    if command -v docker &>/dev/null; then
        if systemctl is-active --quiet docker 2>/dev/null || docker ps &>/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Функция для безопасного применения правил iptables INPUT
apply_iptables_input_rules() {
    local ssh_port="$1"
    shift
    local allowed_ports=("$@")
    
    # Проверяем, есть ли уже правила в INPUT
    local existing_rules=$(iptables -L INPUT -n 2>/dev/null | grep -c "ACCEPT\|DROP" || echo 0)
    
    if [ "$existing_rules" -gt 2 ]; then
        warning "В INPUT уже есть $existing_rules правил"
        echo ""
        echo "Текущие правила INPUT:"
        iptables -L INPUT -n --line-numbers | head -15
        echo ""
        
        echo "Варианты:"
        echo "  1) Очистить INPUT и применить новые правила"
        echo "  2) Добавить новые правила к существующим"
        echo "  3) Отменить настройку файрвола"
        
        local choice=$(ask_menu "Выбор (1-3): " 3)
        
        case "$choice" in
            1)
                iptables -F INPUT
                info "INPUT очищен"
                ;;
            2)
                info "Правила будут добавлены к существующим"
                # Удаляем финальный DROP если есть, чтобы добавить в конец
                iptables -D INPUT -j DROP 2>/dev/null || true
                ;;
            3)
                return 1
                ;;
        esac
    else
        # Очищаем только если правил мало (дефолтное состояние)
        iptables -F INPUT
    fi
    
    # Базовые правила
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    
    # SSH с rate limiting
    iptables -A INPUT -p tcp --dport "$ssh_port" -m state --state NEW -m recent --set --name SSH
    iptables -A INPUT -p tcp --dport "$ssh_port" -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
    iptables -A INPUT -p tcp --dport "$ssh_port" -j ACCEPT
    
    # Разрешенные порты
    for port in "${allowed_ports[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
    done
    
    # Блокировка остального входящего трафика
    iptables -A INPUT -j DROP
    
    return 0
}

# ============================================================================
# ОБРАБОТКА АРГУМЕНТОВ
# ============================================================================

if [ "${1:-}" = "--restore" ] || [ "${1:-}" = "-r" ]; then
    if [ "$EUID" -ne 0 ]; then
        error "Этот скрипт должен запускаться от root"
        exit 1
    fi
    show_restore_menu
fi

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Использование: $0 [опции]"
    echo ""
    echo "Опции:"
    echo "  --restore, -r    Восстановить из резервной копии"
    echo "  --help, -h       Показать эту справку"
    echo ""
    echo "Без аргументов запускает интерактивную настройку безопасности."
    exit 0
fi

# ============================================================================
# ПРОВЕРКИ
# ============================================================================

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    error "Этот скрипт должен запускаться от root"
    exit 1
fi

# Определение ОС
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"
else
    OS_NAME="Unknown"
    OS_VERSION="Unknown"
fi

# Проверка поддержки Ubuntu/Debian
if [[ ! "$ID" =~ ^(ubuntu|debian)$ ]]; then
    error "Скрипт поддерживает только Ubuntu/Debian"
    exit 1
fi

# Переменные для хранения решений
DISABLE_PASSWORD_AUTH=""
DISABLE_ROOT_PASSWORD=""
UPDATE_FAIL2BAN=""
FIREWALL_CHOICE=""
ALLOWED_PORTS=()
POSTGRESQL_ACCESS=""
DOCKER_DETECTED=false

# Проверяем Docker заранее
if is_docker_active; then
    DOCKER_DETECTED=true
fi

# ============================================================================
# ДИАГНОСТИКА СИСТЕМЫ
# ============================================================================

clear
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  ДИАГНОСТИКА СИСТЕМЫ БЕЗОПАСНОСТИ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Проверка ОС
if [[ "$ID" == "ubuntu" ]]; then
    success "ОС: $OS_NAME $OS_VERSION"
else
    info "ОС: $OS_NAME $OS_VERSION"
fi

# Проверка fail2ban
if command -v fail2ban-client &> /dev/null; then
    if systemctl is-active --quiet fail2ban; then
        success "fail2ban: установлен, активен"
    else
        info "fail2ban: установлен, не активен"
    fi
else
    warning "fail2ban: не установлен"
fi

# Проверка ufw
if command -v ufw &> /dev/null; then
    if ufw status | grep -q "Status: active"; then
        success "ufw: установлен, активен"
    else
        info "ufw: установлен, не активен"
    fi
else
    info "ufw: не установлен"
fi

# Проверка iptables
if command -v iptables &> /dev/null; then
    input_rules=$(iptables -L INPUT -n 2>/dev/null | grep -c "ACCEPT\|DROP" || echo 0)
    if [ "$input_rules" -gt 2 ]; then
        success "iptables: установлен, есть правила ($input_rules)"
    else
        info "iptables: установлен, правила не настроены"
    fi
else
    error "iptables: не установлен"
fi

# Проверка Docker
if [ "$DOCKER_DETECTED" = true ]; then
    warning "Docker: АКТИВЕН"
    echo -e "         ${YELLOW}Скрипт НЕ будет изменять FORWARD chain${NC}"
    echo -e "         ${YELLOW}Docker сам управляет трафиком контейнеров${NC}"
fi

echo ""

# Получение открытых портов
OPEN_PORTS=($(get_open_ports))
echo -e "${CYAN}Открытые порты (внешние интерфейсы):${NC}"

declare -A PORT_SERVICES
for port in "${OPEN_PORTS[@]}"; do
    desc=$(get_port_description "$port")
    service=$(get_service_on_port "$port")
    
    if [ -n "$desc" ]; then
        PORT_SERVICES["$port"]="$desc"
        echo "  $port/tcp   - $desc"
    elif [ -n "$service" ]; then
        PORT_SERVICES["$port"]="$service"
        echo "  $port/tcp   - $service"
    else
        PORT_SERVICES["$port"]="неизвестный сервис"
        echo "  $port/tcp   - неизвестный сервис"
    fi
done

if [ ${#OPEN_PORTS[@]} -eq 0 ]; then
    info "Нет портов, открытых на внешних интерфейсах"
fi

echo ""

# Проверка SSH конфигурации
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
SSH_ISSUES=()

if [ -f "$SSH_CONFIG" ]; then
    echo -e "${CYAN}SSH конфигурация:${NC}"
    
    # Определяем порт SSH (проверяем и основной файл, и drop-in)
    SSH_PORT=$(grep -hE "^Port " "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' | head -1)
    if [ -d "$SSH_CONFIG_DIR" ]; then
        SSH_PORT_DROPIN=$(grep -hE "^Port " "$SSH_CONFIG_DIR"/*.conf 2>/dev/null | awk '{print $2}' | head -1 || true)
        [ -n "$SSH_PORT_DROPIN" ] && SSH_PORT="$SSH_PORT_DROPIN"
    fi
    SSH_PORT=${SSH_PORT:-22}
    echo "  Port: $SSH_PORT"
    
    # Проверяем PermitRootLogin (учитываем drop-in файлы)
    ROOT_LOGIN_YES=false
    if grep -qE "^PermitRootLogin\s+yes" "$SSH_CONFIG" 2>/dev/null; then
        ROOT_LOGIN_YES=true
    fi
    if [ -d "$SSH_CONFIG_DIR" ] && ls "$SSH_CONFIG_DIR"/*.conf &>/dev/null; then
        if grep -qE "^PermitRootLogin\s+yes" "$SSH_CONFIG_DIR"/*.conf 2>/dev/null; then
            ROOT_LOGIN_YES=true
        fi
    fi
    if [ "$ROOT_LOGIN_YES" = true ]; then
        warning "PermitRootLogin: yes"
        SSH_ISSUES+=("root_password")
    else
        success "PermitRootLogin: настроен безопасно"
    fi
    
    # Проверяем PasswordAuthentication
    PASS_AUTH_YES=false
    if grep -qE "^PasswordAuthentication\s+yes" "$SSH_CONFIG" 2>/dev/null; then
        PASS_AUTH_YES=true
    fi
    if [ -d "$SSH_CONFIG_DIR" ] && ls "$SSH_CONFIG_DIR"/*.conf &>/dev/null; then
        if grep -qE "^PasswordAuthentication\s+yes" "$SSH_CONFIG_DIR"/*.conf 2>/dev/null; then
            PASS_AUTH_YES=true
        fi
    fi
    if [ "$PASS_AUTH_YES" = true ]; then
        warning "PasswordAuthentication: yes"
        SSH_ISSUES+=("password_auth")
    else
        success "PasswordAuthentication: отключено"
    fi
    
    # Проверяем наличие SSH-ключей
    if check_ssh_keys; then
        success "SSH-ключи: найдены для root"
    else
        warning "SSH-ключи: НЕ найдены для root"
    fi
else
    error "SSH конфигурация не найдена"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  НАСТРОЙКА БЕЗОПАСНОСТИ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# ============================================================================
# [1/5] SSH БЕЗОПАСНОСТЬ
# ============================================================================

echo -e "${CYAN}[1/5] SSH безопасность${NC}"
echo "───────────────────────────────────────────────────────────────"

if [[ " ${SSH_ISSUES[@]} " =~ " password_auth " ]]; then
    echo ""
    warning "Обнаружена парольная аутентификация SSH"
    echo ""
    echo "   Текущая настройка: PasswordAuthentication = yes"
    echo ""
    echo "   Это означает, что ВСЕ пользователи могут входить по паролю."
    echo "   Рекомендуется отключить и использовать только SSH-ключи для"
    echo "   защиты от брутфорс-атак."
    echo ""
    
    # Проверяем наличие SSH-ключей перед отключением паролей
    if ! check_ssh_keys; then
        echo -e "   ${RED}⚠️  ВНИМАНИЕ: SSH-ключи для root НЕ НАЙДЕНЫ!${NC}"
        echo -e "   ${RED}   Если отключить пароли, вы потеряете доступ к серверу!${NC}"
        echo ""
        echo "   Сначала добавьте SSH-ключ:"
        echo "   ssh-copy-id root@<server_ip>"
        echo ""
        warning "Отключение паролей пропущено (нет SSH-ключей)"
    else
        warning "ВНИМАНИЕ: Если отключить пароли, войти смогут только"
        echo "       пользователи с настроенными SSH-ключами!"
        echo ""
        
        if ask_yes_no "Отключить парольную аутентификацию для всех пользователей? (y/n): " "n"; then
            DISABLE_PASSWORD_AUTH="yes"
        fi
    fi
fi

if [[ " ${SSH_ISSUES[@]} " =~ " root_password " ]]; then
    echo ""
    warning "Обнаружен PermitRootLogin = yes"
    echo ""
    echo "   Текущая настройка: PermitRootLogin = yes"
    echo ""
    echo "   Это означает, что пользователь root может входить в систему"
    echo "   ЛЮБЫМ способом (и по паролю, и по ключу)."
    echo ""
    echo "   Рекомендуется изменить на 'prohibit-password':"
    echo "   - root сможет входить ТОЛЬКО по SSH-ключу (безопаснее)"
    echo "   - Парольный вход для root будет запрещен"
    echo ""
    
    if ! check_ssh_keys; then
        echo -e "   ${RED}⚠️  ВНИМАНИЕ: SSH-ключи для root НЕ НАЙДЕНЫ!${NC}"
        echo ""
        warning "Изменение пропущено (нет SSH-ключей)"
    else
        if ask_yes_no "Запретить вход root по паролю? (y/n): " "n"; then
            DISABLE_ROOT_PASSWORD="yes"
        fi
    fi
fi

if [ ${#SSH_ISSUES[@]} -eq 0 ]; then
    success "SSH уже настроен безопасно"
fi

# ============================================================================
# [2/5] FAIL2BAN
# ============================================================================

echo ""
echo -e "${CYAN}[2/5] fail2ban${NC}"
echo "───────────────────────────────────────────────────────────────"

# Новые значения, которые будут применены
NEW_F2B_BANTIME="3600"
NEW_F2B_FINDTIME="600"
NEW_F2B_MAXRETRY="5"
NEW_F2B_SSH_MAXRETRY="3"
NEW_F2B_SSH_BANTIME="7200"

if command -v fail2ban-client &> /dev/null; then
    echo "fail2ban уже установлен"
    echo ""
    
    # Получаем текущие значения
    CURRENT_BANTIME=$(grep -E "^bantime\s*=" /etc/fail2ban/jail.local 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d ' ')
    CURRENT_FINDTIME=$(grep -E "^findtime\s*=" /etc/fail2ban/jail.local 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d ' ')
    CURRENT_MAXRETRY=$(grep -E "^maxretry\s*=" /etc/fail2ban/jail.local 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d ' ')
    
    # Значения по умолчанию если не заданы
    CURRENT_BANTIME=${CURRENT_BANTIME:-"600 (default)"}
    CURRENT_FINDTIME=${CURRENT_FINDTIME:-"600 (default)"}
    CURRENT_MAXRETRY=${CURRENT_MAXRETRY:-"5 (default)"}
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│                    СРАВНЕНИЕ НАСТРОЕК                       │"
    echo "├─────────────────────┬──────────────────┬────────────────────┤"
    echo "│ Параметр            │ Сейчас           │ Станет             │"
    echo "├─────────────────────┼──────────────────┼────────────────────┤"
    printf "│ %-19s │ %-16s │ %-18s │\n" "bantime (общий)" "$CURRENT_BANTIME" "${NEW_F2B_BANTIME} (1 час)"
    printf "│ %-19s │ %-16s │ %-18s │\n" "findtime" "$CURRENT_FINDTIME" "${NEW_F2B_FINDTIME} (10 мин)"
    printf "│ %-19s │ %-16s │ %-18s │\n" "maxretry (общий)" "$CURRENT_MAXRETRY" "$NEW_F2B_MAXRETRY"
    echo "├─────────────────────┴──────────────────┴────────────────────┤"
    echo "│ Специальные настройки для SSH:                              │"
    echo "├─────────────────────┬──────────────────┬────────────────────┤"
    printf "│ %-19s │ %-16s │ %-18s │\n" "ssh maxretry" "-" "${NEW_F2B_SSH_MAXRETRY} попытки"
    printf "│ %-19s │ %-16s │ %-18s │\n" "ssh bantime" "-" "${NEW_F2B_SSH_BANTIME} (2 часа)"
    echo "└─────────────────────┴──────────────────┴────────────────────┘"
    echo ""
    echo -e "${BLUE}Пояснение:${NC}"
    echo "  • bantime  — время блокировки IP после превышения лимита"
    echo "  • findtime — окно времени для подсчёта неудачных попыток"
    echo "  • maxretry — максимум неудачных попыток до блокировки"
    echo ""
    
    if ask_yes_no "Применить новые настройки fail2ban? (y/n): " "n"; then
        UPDATE_FAIL2BAN="yes"
    fi
else
    echo "fail2ban не установлен"
    echo ""
    echo -e "${BLUE}Что такое fail2ban?${NC}"
    echo "  Защищает от брутфорс-атак, блокируя IP-адреса"
    echo "  после нескольких неудачных попыток входа."
    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│              НАСТРОЙКИ, КОТОРЫЕ БУДУТ ПРИМЕНЕНЫ             │"
    echo "├─────────────────────┬───────────────────────────────────────┤"
    printf "│ %-19s │ %-37s │\n" "bantime (общий)" "${NEW_F2B_BANTIME} сек (1 час)"
    printf "│ %-19s │ %-37s │\n" "findtime" "${NEW_F2B_FINDTIME} сек (10 мин)"
    printf "│ %-19s │ %-37s │\n" "maxretry (общий)" "${NEW_F2B_MAXRETRY} попыток"
    echo "├─────────────────────┴───────────────────────────────────────┤"
    echo "│ Специальные настройки для SSH:                              │"
    echo "├─────────────────────┬───────────────────────────────────────┤"
    printf "│ %-19s │ %-37s │\n" "ssh maxretry" "${NEW_F2B_SSH_MAXRETRY} попытки"
    printf "│ %-19s │ %-37s │\n" "ssh bantime" "${NEW_F2B_SSH_BANTIME} сек (2 часа)"
    echo "└─────────────────────┴───────────────────────────────────────┘"
    echo ""
    
    if ask_yes_no "Установить fail2ban с этими настройками? (y/n): " "y"; then
        UPDATE_FAIL2BAN="yes"
    fi
fi

# ============================================================================
# [3/5] ФАЙРВОЛ
# ============================================================================

echo ""
echo -e "${CYAN}[3/5] Файрвол${NC}"
echo "───────────────────────────────────────────────────────────────"

# Предупреждение о Docker
if [ "$DOCKER_DETECTED" = true ]; then
    echo ""
    info "Docker обнаружен. Скрипт настроит только INPUT chain."
    echo "    FORWARD chain останется под управлением Docker."
    echo "    Это безопасно — Docker сам изолирует контейнеры."
    echo ""
fi

FIREWALLS_FOUND=()
if command -v iptables &> /dev/null; then
    FIREWALLS_FOUND+=("iptables")
fi
if command -v ufw &> /dev/null; then
    FIREWALLS_FOUND+=("ufw")
fi

if [ ${#FIREWALLS_FOUND[@]} -eq 0 ]; then
    error "Не найдено ни одного файрвола"
else
    echo "Обнаружены следующие файрволы:"
    for fw in "${FIREWALLS_FOUND[@]}"; do
        if [ "$fw" = "iptables" ]; then
            success "iptables - доступен"
        elif [ "$fw" = "ufw" ]; then
            if ufw status | grep -q "Status: active"; then
                success "ufw - активен"
            else
                info "ufw - не активен"
            fi
        fi
    done
    echo ""
    echo "Какой файрвол использовать?"
    echo "  1) iptables (прямое управление, больше контроля)"
    echo "  2) ufw (проще в управлении, рекомендуется)"
    echo "  3) Пропустить настройку файрвола"
    
    FIREWALL_CHOICE=$(ask_menu "Выбор (1-3): " 3)
fi

# ============================================================================
# [4/5] НАСТРОЙКА ПОРТОВ
# ============================================================================

if [ "$FIREWALL_CHOICE" != "3" ] && [ -n "$FIREWALL_CHOICE" ]; then
    echo ""
    echo -e "${CYAN}[4/5] Настройка портов${NC}"
    echo "───────────────────────────────────────────────────────────────"
    
    if [ ${#OPEN_PORTS[@]} -eq 0 ]; then
        info "Нет открытых портов на внешних интерфейсах (кроме SSH)"
    else
        echo "Обнаружены следующие открытые порты. Выберите, какие разрешить:"
        echo ""
        echo -e "${GREEN}SSH ($SSH_PORT) будет разрешен автоматически${NC}"
        echo ""
        
        for port in "${OPEN_PORTS[@]}"; do
            # Пропускаем SSH порт - он всегда разрешен
            if [ "$port" = "$SSH_PORT" ]; then
                continue
            fi
            
            service_info="${PORT_SERVICES[$port]:-неизвестный сервис}"
            port_desc=$(get_port_description "$port")
            
            if [ -n "$port_desc" ]; then
                echo "Порт $port ($port_desc)"
            else
                echo "Порт $port - $service_info"
            fi
            
            if ask_yes_no "  Разрешить внешний доступ? (y/n): " "n"; then
                ALLOWED_PORTS+=("$port")
            fi
            echo ""
        done
    fi
fi

# ============================================================================
# [5/5] POSTGRESQL
# ============================================================================

if [[ " ${OPEN_PORTS[@]} " =~ " 5432 " ]] && [ "$FIREWALL_CHOICE" != "3" ]; then
    # Проверяем, не добавлен ли уже 5432 в разрешенные порты
    if [[ ! " ${ALLOWED_PORTS[@]} " =~ " 5432 " ]]; then
        echo ""
        echo -e "${CYAN}[5/5] PostgreSQL (порт 5432)${NC}"
        echo "───────────────────────────────────────────────────────────────"
        warning "Обнаружен PostgreSQL на порту 5432"
        echo ""
        echo "   По умолчанию база данных должна быть доступна только локально."
        echo "   Внешний доступ открывает уязвимость для атак."
        echo ""
        echo "Как настроить доступ к PostgreSQL?"
        echo "  1) Только localhost (рекомендуется) ✓"
        echo "     → Доступ только с самого сервера (127.0.0.1)"
        echo ""
        echo "  2) Разрешить внешний доступ"
        echo "     → Доступ из интернета (⚠️ требует дополнительной защиты)"
        echo ""
        
        POSTGRESQL_ACCESS=$(ask_menu "Выбор (1-2): " 2)
    else
        # PostgreSQL уже в разрешенных портах
        POSTGRESQL_ACCESS="2"
    fi
fi

# ============================================================================
# ПОДТВЕРЖДЕНИЕ ИЗМЕНЕНИЙ
# ============================================================================

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  ПОДТВЕРЖДЕНИЕ ИЗМЕНЕНИЙ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

CHANGES_COUNT=0

echo "Будут применены следующие изменения:"
echo ""

if [ "$DISABLE_PASSWORD_AUTH" = "yes" ] || [ "$DISABLE_ROOT_PASSWORD" = "yes" ]; then
    echo "SSH:"
    [ "$DISABLE_PASSWORD_AUTH" = "yes" ] && echo -e "  ${GREEN}[✓]${NC} PasswordAuthentication: yes → no"
    [ "$DISABLE_ROOT_PASSWORD" = "yes" ] && echo -e "  ${GREEN}[✓]${NC} PermitRootLogin: yes → prohibit-password"
    echo ""
    CHANGES_COUNT=$((CHANGES_COUNT + 1))
fi

if [ "$UPDATE_FAIL2BAN" = "yes" ]; then
    echo -e "  ${GREEN}[✓]${NC} fail2ban: установка/обновление конфигурации"
    echo ""
    CHANGES_COUNT=$((CHANGES_COUNT + 1))
fi

if [ "$FIREWALL_CHOICE" != "3" ] && [ -n "$FIREWALL_CHOICE" ]; then
    # Исправлено: убрали local
    fw_name="iptables"
    [ "$FIREWALL_CHOICE" = "2" ] && fw_name="ufw"
    
    echo "Файрвол ($fw_name):"
    echo -e "  ${GREEN}[✓]${NC} Разрешить: SSH ($SSH_PORT)"
    
    for port in "${ALLOWED_PORTS[@]}"; do
        # Исправлено: убрали local
        service_info="${PORT_SERVICES[$port]:-порт}"
        echo -e "  ${GREEN}[✓]${NC} Разрешить: $service_info ($port)"
    done
    
    if [ "$POSTGRESQL_ACCESS" = "1" ]; then
        echo -e "  ${GREEN}[✓]${NC} PostgreSQL (5432): только localhost"
    elif [ "$POSTGRESQL_ACCESS" = "2" ]; then
        echo -e "  ${GREEN}[✓]${NC} PostgreSQL (5432): внешний доступ разрешен"
    fi
    
    if [ "$DOCKER_DETECTED" = true ]; then
        echo -e "  ${BLUE}[i]${NC} Docker: FORWARD chain НЕ изменяется"
    fi
    
    echo -e "  ${GREEN}[✓]${NC} Блокировать все остальные порты"
    echo ""
    CHANGES_COUNT=$((CHANGES_COUNT + 1))
fi

if [ $CHANGES_COUNT -eq 0 ]; then
    info "Изменений не запланировано"
    exit 0
fi

warning "ВАЖНО: Перед применением будут созданы резервные копии"
echo "           всех изменяемых файлов в $BACKUP_DIR"
echo ""
echo "       Для восстановления используйте: $0 --restore"
echo ""

if ! ask_yes_no "Применить изменения? (y/n): " "n"; then
    echo ""
    info "Отменено пользователем"
    exit 0
fi

# ============================================================================
# ПРИМЕНЕНИЕ ИЗМЕНЕНИЙ
# ============================================================================

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  ПРИМЕНЕНИЕ ИЗМЕНЕНИЙ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Создание директории для резервных копий
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Создание резервных копий..."

# Резервная копия SSH
if [ "$DISABLE_PASSWORD_AUTH" = "yes" ] || [ "$DISABLE_ROOT_PASSWORD" = "yes" ]; then
    cp "$SSH_CONFIG" "$BACKUP_DIR/sshd_config.backup.$TIMESTAMP"
    success "SSH: $BACKUP_DIR/sshd_config.backup.$TIMESTAMP"
fi

# Резервная копия iptables (всегда, если меняем файрвол)
if [ "$FIREWALL_CHOICE" = "1" ] || [ "$FIREWALL_CHOICE" = "2" ]; then
    iptables-save > "$BACKUP_DIR/iptables_backup_$TIMESTAMP.rules"
    success "iptables: $BACKUP_DIR/iptables_backup_$TIMESTAMP.rules"
fi

# Резервная копия fail2ban
if [ "$UPDATE_FAIL2BAN" = "yes" ] && [ -f /etc/fail2ban/jail.local ]; then
    cp /etc/fail2ban/jail.local "$BACKUP_DIR/fail2ban_jail.local.backup.$TIMESTAMP"
    success "fail2ban: $BACKUP_DIR/fail2ban_jail.local.backup.$TIMESTAMP"
fi

echo ""
echo "Применение изменений..."
echo ""

# Применение изменений SSH
if [ "$DISABLE_PASSWORD_AUTH" = "yes" ] || [ "$DISABLE_ROOT_PASSWORD" = "yes" ]; then
    if [ "$DISABLE_PASSWORD_AUTH" = "yes" ]; then
        # Безопасное изменение: сначала комментируем старое, потом добавляем новое
        sed -i 's/^PasswordAuthentication.*/#&/' "$SSH_CONFIG"
        echo "PasswordAuthentication no" >> "$SSH_CONFIG"
    fi
    
    if [ "$DISABLE_ROOT_PASSWORD" = "yes" ]; then
        sed -i 's/^PermitRootLogin.*/#&/' "$SSH_CONFIG"
        echo "PermitRootLogin prohibit-password" >> "$SSH_CONFIG"
    fi
    
    # Проверяем конфигурацию перед перезапуском
    if sshd -t 2>/dev/null; then
        systemctl restart sshd
        success "SSH конфигурация обновлена"
    else
        error "Ошибка в SSH конфигурации! Восстанавливаю из бэкапа..."
        cp "$BACKUP_DIR/sshd_config.backup.$TIMESTAMP" "$SSH_CONFIG"
        error "SSH конфигурация восстановлена. Проверьте вручную."
    fi
fi

# Применение изменений fail2ban
if [ "$UPDATE_FAIL2BAN" = "yes" ]; then
    if ! command -v fail2ban-client &> /dev/null; then
        info "Установка fail2ban..."
        apt-get update -qq
        apt-get install -y -qq fail2ban
    fi
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 7200
findtime = 600
EOF
    
    systemctl restart fail2ban
    systemctl enable fail2ban
    success "fail2ban настроен и запущен"
fi

# Применение изменений файрвола
if [ "$FIREWALL_CHOICE" = "1" ]; then
    # iptables
    
    # Собираем все разрешенные порты
    ALL_ALLOWED_PORTS=("${ALLOWED_PORTS[@]}")
    
    # PostgreSQL
    if [ "$POSTGRESQL_ACCESS" = "1" ]; then
        # Только localhost — добавим отдельное правило после основных
        :
    elif [ "$POSTGRESQL_ACCESS" = "2" ]; then
        ALL_ALLOWED_PORTS+=("5432")
    fi
    
    # Применяем правила INPUT (НЕ трогаем FORWARD!)
    if apply_iptables_input_rules "$SSH_PORT" "${ALL_ALLOWED_PORTS[@]}"; then
        
        # Отдельное правило для PostgreSQL localhost
        if [ "$POSTGRESQL_ACCESS" = "1" ]; then
            # Вставляем перед финальным DROP
            iptables -I INPUT -p tcp --dport 5432 -s 127.0.0.1 -j ACCEPT
        fi
        
        # Сохранение правил
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save 2>/dev/null
        elif [ -d /etc/iptables ]; then
            iptables-save > /etc/iptables/rules.v4
        fi
        
        success "iptables INPUT настроен и сохранен"
        
        if [ "$DOCKER_DETECTED" = true ]; then
            info "FORWARD chain не изменялся (управляется Docker)"
        fi
    else
        warning "Настройка файрвола отменена"
    fi
    
elif [ "$FIREWALL_CHOICE" = "2" ]; then
    # ufw
    
    warning "ufw сбросит текущие правила"
    if ! ask_yes_no "Продолжить? (y/n): " "y"; then
        warning "Настройка ufw отменена"
    else
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        
        ufw allow "$SSH_PORT/tcp"
        
        for port in "${ALLOWED_PORTS[@]}"; do
            ufw allow "$port/tcp"
        done
        
        if [ "$POSTGRESQL_ACCESS" = "1" ]; then
            ufw allow from 127.0.0.1 to any port 5432
        elif [ "$POSTGRESQL_ACCESS" = "2" ]; then
            ufw allow 5432/tcp
        fi
        
        ufw --force enable
        success "ufw настроен и активирован"
        
        if [ "$DOCKER_DETECTED" = true ]; then
            info "Docker может потребовать перезапуска: systemctl restart docker"
        fi
    fi
fi

# ============================================================================
# ЗАВЕРШЕНИЕ
# ============================================================================

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ЗАВЕРШЕНО${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}Статус защиты:${NC}"
[ "$DISABLE_PASSWORD_AUTH" = "yes" ] && success "SSH: пароли отключены"
[ "$DISABLE_ROOT_PASSWORD" = "yes" ] && success "SSH: root только по ключу"
[ "$UPDATE_FAIL2BAN" = "yes" ] && success "fail2ban: активен, защита SSH включена"
[ "$FIREWALL_CHOICE" = "1" ] && success "iptables: INPUT настроен"
[ "$FIREWALL_CHOICE" = "2" ] && success "ufw: настроен и активен"
[ "$POSTGRESQL_ACCESS" = "1" ] && success "PostgreSQL: доступен только локально"
[ "$DOCKER_DETECTED" = true ] && info "Docker: FORWARD не изменялся"

echo ""
echo -e "${CYAN}Резервные копии:${NC} $BACKUP_DIR"
echo -e "${CYAN}Восстановление:${NC}  $0 --restore"
echo ""

echo -e "${CYAN}Полезные команды:${NC}"
echo ""
echo -e "  ${BLUE}Просмотр заблокированных IP (fail2ban):${NC}"
echo -e "    fail2ban-client status sshd"
echo ""
echo -e "  ${BLUE}Разблокировка IP:${NC}"
echo -e "    fail2ban-client set sshd unbanip <IP_ADDRESS>"
echo ""
if [ "$FIREWALL_CHOICE" = "1" ]; then
    echo -e "  ${BLUE}Просмотр правил iptables:${NC}"
    echo -e "    iptables -L INPUT -n -v --line-numbers"
elif [ "$FIREWALL_CHOICE" = "2" ]; then
    echo -e "  ${BLUE}Просмотр правил ufw:${NC}"
    echo -e "    ufw status verbose"
fi
echo ""

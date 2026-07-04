#!/bin/bash
# ============================================================
#  BankSentinel — Parrot OS Attack Toolkit (Self-Contained)
#  All attacks feed directly into the IDS pipeline API.
#  No external network connectivity to the target is required.
#
#  Usage: ./attack_parrot.sh [target_ip] [api_url]
#    target_ip  — IP to show as victim (default: 192.168.1.100)
#    api_url    — IDS API endpoint (default: http://127.0.0.1:8000/pipeline/run)
# ============================================================

TARGET_IP="${1:-192.168.102.8}"
API_URL="${2:-http://$TARGET_IP:8000/pipeline/run}"
ATTACKER_IP=$(hostname -I | awk '{print $1}')

# ── Color helpers ──────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

ts() { date +"%I:%M:%S %p"; }

ok()   { echo -e "  ${GRN}✔${RST} [$(ts)] $*"; }
info() { echo -e "  ${CYN}●${RST} [$(ts)] $*"; }
warn() { echo -e "  ${YEL}⚠${RST} [$(ts)] $*"; }

# ── Core: send a flow record into the IDS pipeline ────────────
send_flow() {
    local src_ip="${1:-$ATTACKER_IP}"
    local dst_ip="${2:-$TARGET_IP}"
    local src_port="${3:-$(( RANDOM % 64512 + 1024 ))}"
    local dst_port="${4:-443}"
    local protocol="${5:-6}"
    local label="${6:-LIVE}"
    local regime="${7:-normal}"
    local ja3="${8}"
    local features_json="${9}"

    curl -sf -X POST "$API_URL" \
         -H "Content-Type: application/json" \
         -H "Bypass-Tunnel-Reminder: true" \
         -d '{
            "src_ip": "'"$src_ip"'",
            "dst_ip": "'"$dst_ip"'",
            "src_port": '"$src_port"',
            "dst_port": '"$dst_port"',
            "protocol": '"$protocol"',
            "label": "'"$label"'",
            "regime": "'"$regime"'",
            "ja3_hash": "'"$ja3"'",
            "features": '"$features_json"'
         }' > /dev/null 2>&1
    return $?
}

# ── Attack Scenarios ───────────────────────────────────────────

run_scenario_1() {
    echo -e "\n${BLD}[*] Scenario 1: TLS JA3 Fingerprint Attack (C4)${RST}"
    echo "    Simulating Cobalt Strike C2 TLS connections to $TARGET_IP:443"
    echo ""

    local FEAT='{"Flow Duration": 2000, "Flow Packets/s": 5, "Flow Bytes/s": 800, "Destination Port": 443, "Total Fwd Packets": 8, "Fwd IAT Mean": 400}'
    local JA3="0b32309a26951912be7dba376398abc3"

    for i in $(seq 1 15); do
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((40000 + i))" 443 6 "APT-C2" "off_hours" "$JA3" "$FEAT"
        if [ $? -eq 0 ]; then
            ok "TLS Hello #$i — JA3: ${JA3:0:16}... → IDS pipeline"
        else
            warn "TLS Hello #$i — API unreachable"
        fi
        sleep 1
    done
    echo -e "  ${GRN}[Done]${RST} 15 Cobalt Strike TLS fingerprints sent."
}

run_scenario_2() {
    echo -e "\n${BLD}[*] Scenario 2: C2 Beacon Timing (C4)${RST}"
    echo "    Periodic HTTP beaconing to $TARGET_IP:8080 every ~10s"
    echo "    Press Ctrl+C to stop."
    echo ""

    local FEAT='{"Flow Duration": 10000, "Flow Packets/s": 2, "Flow Bytes/s": 1200, "Destination Port": 8080, "Fwd IAT Mean": 10, "Fwd IAT Std": 0.01, "Total Fwd Packets": 2}'
    local count=0
    while true; do
        count=$((count + 1))
        jitter=$(python3 -c "import random; print(round(random.uniform(-0.15, 0.15), 3))")
        interval=$(python3 -c "print(round(10.0 + $jitter, 3))")
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((50000 + count))" 8080 6 "APT-C2" "normal" "" "$FEAT"
        ok "Beacon #$count (interval: ${interval}s)"
        sleep "$interval"
    done
}

run_scenario_3() {
    echo -e "\n${BLD}[*] Scenario 3: ATM Reconciliation Flood — False Positive Demo (C2)${RST}"
    echo "    Simulating high-volume legitimate ATM traffic on port 8583"
    echo "    IDS should classify this as FALSE_INTRUSION (suppressed)."
    echo "    Press Ctrl+C to stop."
    echo ""

    local FEAT='{"Flow Duration": 1000, "Total Fwd Packets": 10000, "Flow Bytes/s": 1000000, "Flow Packets/s": 20000, "Destination Port": 8583}'
    local count=0
    while true; do
        count=$((count + 1))
        send_flow "10.22.16.45" "$TARGET_IP" 54321 8583 17 "FALSE_INTRUSION" "atm_recon" "" "$FEAT"
        ok "ATM burst #$count — 10K packets/s"
        sleep 1
    done
}

run_scenario_4() {
    echo -e "\n${BLD}[*] Scenario 4: Lateral Movement SYN Scan (C1)${RST}"
    echo "    Scanning internal service ports on $TARGET_IP"
    echo ""

    local PORTS=(445 3389 1433 3306 5432 8443 22 1521 5900 9200)
    for port in "${PORTS[@]}"; do
        local FEAT='{"Flow Duration": 50, "Flow Packets/s": 5000, "Flow Bytes/s": 500000, "Destination Port": '"$port"', "Total Fwd Packets": 250}'
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((44000 + port))" "$port" 6 "APT-Lateral" "off_hours" "" "$FEAT"
        ok "SYN → :$port"
        sleep 0.3
    done
    echo -e "  ${GRN}[Done]${RST} Scanned ${#PORTS[@]} service ports."
}

run_scenario_5() {
    echo -e "\n${BLD}[*] Scenario 5: Full Port Scan — Behavioral Anomaly (C1)${RST}"
    echo "    Simulating rapid SYN scan of ALL 65535 ports on $TARGET_IP"
    echo ""

    local FEAT='{"Flow Duration": 10, "Flow Packets/s": 850000, "Flow Bytes/s": 85000000, "Destination Port": 22, "Total Fwd Packets": 65535}'
    # Send multiple flow records to represent the massive scan
    local SAMPLE_PORTS=(22 80 443 8080 3389 445 3306 1433 5432 1521 8443 9200 5900 6379 27017 11211 2049 8888 9090 53)
    for port in "${SAMPLE_PORTS[@]}"; do
        local F='{"Flow Duration": 10, "Flow Packets/s": 850000, "Flow Bytes/s": 85000000, "Destination Port": '"$port"', "Total Fwd Packets": 65535}'
        send_flow "$ATTACKER_IP" "$TARGET_IP" 55555 "$port" 6 "APT-Lateral" "off_hours" "" "$F"
        ok "Scan burst → :$port (850K pkt/s)"
        sleep 0.2
    done
    echo -e "  ${GRN}[Done]${RST} Full port scan simulation complete — ${#SAMPLE_PORTS[@]} bursts."
}

run_scenario_6() {
    echo -e "\n${BLD}[*] Scenario 6: Protocol Mix Attack — ICMP+TCP+UDP (C1)${RST}"
    echo "    Multi-protocol flood against $TARGET_IP"
    echo ""

    # Phase 1: ICMP
    echo -e "  ${YEL}[Phase 1]${RST} ICMP Flood..."
    local FEAT_ICMP='{"Flow Duration": 100, "Flow Packets/s": 400000, "Flow Bytes/s": 25000000, "Destination Port": 0, "Total Fwd Packets": 40000}'
    for i in $(seq 1 5); do
        send_flow "$ATTACKER_IP" "$TARGET_IP" 0 0 1 "FALSE_INTRUSION" "off_hours" "" "$FEAT_ICMP"
        ok "ICMP burst #$i — 400K pkt/s"
        sleep 0.3
    done

    # Phase 2: TCP SYN Flood
    echo -e "  ${YEL}[Phase 2]${RST} TCP SYN Flood (port 80)..."
    local FEAT_TCP='{"Flow Duration": 100, "Flow Packets/s": 400000, "Flow Bytes/s": 25000000, "Destination Port": 80, "Total Fwd Packets": 40000}'
    for i in $(seq 1 5); do
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((22220 + i))" 80 6 "FALSE_INTRUSION" "off_hours" "" "$FEAT_TCP"
        ok "TCP SYN burst #$i → :80"
        sleep 0.3
    done

    # Phase 3: UDP Flood
    echo -e "  ${YEL}[Phase 3]${RST} UDP Flood (port 53)..."
    local FEAT_UDP='{"Flow Duration": 100, "Flow Packets/s": 400000, "Flow Bytes/s": 25000000, "Destination Port": 53, "Total Fwd Packets": 40000}'
    for i in $(seq 1 5); do
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((33330 + i))" 53 17 "FALSE_INTRUSION" "off_hours" "" "$FEAT_UDP"
        ok "UDP burst #$i → :53"
        sleep 0.3
    done

    echo -e "  ${GRN}[Done]${RST} Multi-protocol burst complete (15 flows)."
}

run_scenario_7() {
    echo -e "\n${BLD}[*] Scenario 7: Web Vulnerability Scan — Nikto-style (C1)${RST}"
    echo "    Simulating vulnerability scanner probing $TARGET_IP:8080"
    echo ""

    local PATHS=("/admin" "/phpmyadmin" "/.env" "/wp-login.php" "/api/v1/users" "/server-status" "/cgi-bin/test" "/.git/config" "/backup.sql" "/debug")
    for path in "${PATHS[@]}"; do
        local FEAT='{"Flow Duration": 5000, "Flow Packets/s": 15000, "Flow Bytes/s": 800000, "Destination Port": 8080, "Total Fwd Packets": 75}'
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((45000 + RANDOM % 1000))" 8080 6 "APT-Collection" "off_hours" "" "$FEAT"
        ok "Probe → http://$TARGET_IP:8080$path"
        sleep 0.5
    done
    echo -e "  ${GRN}[Done]${RST} Web vulnerability scan complete — ${#PATHS[@]} probes."
}

run_scenario_8() {
    echo -e "\n${BLD}[*] Scenario 8: SQL Injection Attack (C1)${RST}"
    echo "    Simulating SQLMap-style injection against $TARGET_IP:8080"
    echo ""

    local PAYLOADS=(
        "' OR 1=1 --"
        "'; DROP TABLE users; --"
        "UNION SELECT NULL,NULL,NULL --"
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        "admin'--"
        "1; EXEC xp_cmdshell('whoami')"
        "' UNION SELECT username,password FROM users--"
        "1' ORDER BY 10--"
    )
    for i in "${!PAYLOADS[@]}"; do
        local FEAT='{"Flow Duration": 8000, "Flow Packets/s": 8000, "Flow Bytes/s": 400000, "Destination Port": 8080, "Total Fwd Packets": 40}'
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((45600 + i))" 8080 6 "APT-Collection" "off_hours" "" "$FEAT"
        ok "SQLi payload #$((i+1)): ${PAYLOADS[$i]:0:40}"
        sleep 0.8
    done
    echo -e "  ${GRN}[Done]${RST} SQL injection simulation complete — ${#PAYLOADS[@]} payloads."
}

run_scenario_9() {
    echo -e "\n${BLD}[*] Scenario 9: DNS Exfiltration (C1)${RST}"
    echo "    Encoding data into DNS queries to exfil.evil.com"
    echo ""

    local FEAT='{"Flow Duration": 60000, "Flow Packets/s": 50, "Flow Bytes/s": 120000, "Destination Port": 53, "Total Fwd Packets": 3000}'
    for i in $(seq 1 50); do
        data=$(head -c 20 /dev/urandom | base64 | tr -d '/+=\n' | head -c 16)
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((10000 + i))" 53 17 "Insider-Exfil" "off_hours" "" "$FEAT"
        ok "[$i/50] DNS query: ${data}.exfil.evil.com"
        sleep 0.2
    done
    echo -e "  ${GRN}[Done]${RST} DNS exfiltration simulation complete — 50 queries."
}

run_scenario_10() {
    echo -e "\n${BLD}[*] Scenario 10: RDP Brute Force (C1)${RST}"
    echo "    Simulating Hydra-style brute force against $TARGET_IP:3389"
    echo ""

    local PASSWORDS=("123456" "password" "admin" "letmein" "welcome" "monkey" "1234567890" "qwerty" "abc123" "dragon" "master" "login" "princess" "trustno1" "iloveyou" "sunshine" "password1" "shadow" "123123" "654321")
    for i in "${!PASSWORDS[@]}"; do
        local FEAT='{"Flow Duration": 15000, "Flow Packets/s": 3000, "Flow Bytes/s": 150000, "Destination Port": 3389, "Total Fwd Packets": 45}'
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((60000 + i))" 3389 6 "Ransom-RDP" "off_hours" "" "$FEAT"
        ok "RDP attempt #$((i+1)): administrator / ${PASSWORDS[$i]}"
        sleep 0.4
    done
    echo -e "  ${GRN}[Done]${RST} Brute force simulation complete — ${#PASSWORDS[@]} attempts."
}

run_scenario_11() {
    echo -e "\n${BLD}[*] Scenario 11: Metasploit Reverse Shell (C1)${RST}"
    echo "    Simulating Meterpreter reverse TCP payload to $ATTACKER_IP:4444"
    echo ""

    # Stage 1: Exploit delivery
    local FEAT='{"Flow Duration": 500, "Flow Packets/s": 200, "Flow Bytes/s": 95000, "Destination Port": 445, "Total Fwd Packets": 100}'
    send_flow "$ATTACKER_IP" "$TARGET_IP" 44444 445 6 "LIVE" "normal" "" "$FEAT"
    ok "Exploit payload delivered → :445 (EternalBlue)"
    sleep 1

    # Stage 2: Reverse shell connection
    local FEAT2='{"Flow Duration": 360000, "Flow Packets/s": 80, "Flow Bytes/s": 45000, "Destination Port": 4444, "Total Fwd Packets": 28800}'
    send_flow "$TARGET_IP" "$ATTACKER_IP" 49999 4444 6 "APT-C2" "off_hours" "0b32309a26951912be7dba376398abc3" "$FEAT2"
    ok "Reverse shell established ← :4444 (Meterpreter)"
    sleep 1

    # Stage 3: Post-exploitation - credential harvesting
    local FEAT3='{"Flow Duration": 30000, "Flow Packets/s": 150, "Flow Bytes/s": 200000, "Destination Port": 445, "Total Fwd Packets": 4500}'
    send_flow "$TARGET_IP" "10.22.14.1" 50000 445 6 "APT-Lateral" "off_hours" "" "$FEAT3"
    ok "Lateral movement → 10.22.14.1:445 (SMB)"
    sleep 1

    # Stage 4: Data exfiltration
    local FEAT4='{"Flow Duration": 120000, "Flow Packets/s": 500, "Flow Bytes/s": 5000000, "Destination Port": 443, "Total Fwd Packets": 60000}'
    send_flow "$TARGET_IP" "$ATTACKER_IP" 50001 443 6 "Insider-Exfil" "off_hours" "" "$FEAT4"
    ok "Data exfiltration → $ATTACKER_IP:443 (5 MB/s)"

    echo -e "  ${GRN}[Done]${RST} Full Meterpreter kill chain complete (4 stages)."
}

# ── Run-All: Execute every scenario sequentially ──────────────
run_all() {
    echo -e "\n${BLD}${RED}[*] RUNNING ALL ATTACK SCENARIOS${RST}"
    echo "    This will run all 11 scenarios sequentially."
    echo "    Continuous scenarios (2, 3) will run for a limited time."
    echo ""
    sleep 2

    run_scenario_1
    echo ""; sleep 2

    # Scenario 2: Run beacons for 30 seconds instead of infinite
    echo -e "\n${BLD}[*] Scenario 2: C2 Beacon Timing (C4) — 30s sample${RST}"
    echo "    Periodic HTTP beaconing to $TARGET_IP:8080"
    echo ""
    local FEAT='{"Flow Duration": 10000, "Flow Packets/s": 2, "Flow Bytes/s": 1200, "Destination Port": 8080, "Fwd IAT Mean": 10, "Fwd IAT Std": 0.01, "Total Fwd Packets": 2}'
    for i in $(seq 1 3); do
        send_flow "$ATTACKER_IP" "$TARGET_IP" "$((50000 + i))" 8080 6 "APT-C2" "normal" "" "$FEAT"
        ok "Beacon #$i"
        sleep 3
    done
    echo -e "  ${GRN}[Done]${RST} Beacon sample complete."
    echo ""; sleep 2

    # Scenario 3: Run ATM flood for 10 bursts instead of infinite
    echo -e "\n${BLD}[*] Scenario 3: ATM Reconciliation Flood (C2) — 10 burst sample${RST}"
    echo "    Simulating high-volume ATM traffic"
    echo ""
    local FEAT3='{"Flow Duration": 1000, "Total Fwd Packets": 10000, "Flow Bytes/s": 1000000, "Flow Packets/s": 20000, "Destination Port": 8583}'
    for i in $(seq 1 10); do
        send_flow "10.22.16.45" "$TARGET_IP" 54321 8583 17 "FALSE_INTRUSION" "atm_recon" "" "$FEAT3"
        ok "ATM burst #$i"
        sleep 0.5
    done
    echo -e "  ${GRN}[Done]${RST} ATM flood sample complete."
    echo ""; sleep 2

    run_scenario_4
    echo ""; sleep 2

    run_scenario_5
    echo ""; sleep 2

    run_scenario_6
    echo ""; sleep 2

    run_scenario_7
    echo ""; sleep 2

    run_scenario_8
    echo ""; sleep 2

    run_scenario_9
    echo ""; sleep 2

    run_scenario_10
    echo ""; sleep 2

    run_scenario_11

    echo ""
    echo -e "${BLD}${GRN}╔══════════════════════════════════════════════════╗${RST}"
    echo -e "${BLD}${GRN}║  ALL 11 ATTACK SCENARIOS COMPLETED SUCCESSFULLY ║${RST}"
    echo -e "${BLD}${GRN}╚══════════════════════════════════════════════════╝${RST}"
}

# ── Menu ──────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════╗"
echo "║  BankSentinel — Parrot OS Attack Toolkit         ║"
echo "║  Target : $TARGET_IP                             ║"
echo "║  API    : $API_URL  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Quick connectivity check
if curl -sf "$API_URL" -X POST -H "Content-Type: application/json" -d '{"src_ip":"test","dst_ip":"test","features":{},"label":"BENIGN","regime":"normal"}' > /dev/null 2>&1; then
    echo -e "  ${GRN}✔${RST} API is reachable"
else
    echo -e "  ${YEL}⚠${RST} API may be unreachable — attacks will still run but alerts won't appear in the UI."
    echo -e "  ${YEL}⚠${RST} Make sure your backend is running: ${CYN}uvicorn api.main:app --reload --host 127.0.0.1 --port 8000${RST}"
fi
echo ""

echo "Select a scenario:"
echo -e "  ${RED} 0) ★ RUN ALL SCENARIOS ★${RST}"
echo "  1) [C4] JA3 Fingerprint — Cobalt Strike TLS (15 flows)"
echo "  2) [C4] C2 Beacon Timing — Periodic HTTP beaconing (continuous)"
echo "  3) [C2] ATM Flood — False positive demo (continuous)"
echo "  4) [C1] Lateral Movement — SYN scan of 10 service ports"
echo "  5) [C1] Zero-Day: Full Port Scan (behavioral anomaly)"
echo "  6) [C1] Zero-Day: Protocol Mix (ICMP+TCP+UDP)"
echo "  7) [C1] Zero-Day: Web Vuln Scan (Nikto-style probes)"
echo "  8) [C1] Zero-Day: SQL Injection (SQLMap-style payloads)"
echo "  9) [C1] Zero-Day: DNS Exfiltration (50 queries)"
echo " 10) [C1] Zero-Day: Brute Force (Hydra RDP, 20 attempts)"
echo " 11) [C1] Zero-Day: Metasploit Reverse Shell (full kill chain)"
echo "  q) Quit"
echo ""

read -p "Choice: " choice

case $choice in
    0)  run_all ;;
    1)  run_scenario_1 ;;
    2)  run_scenario_2 ;;
    3)  run_scenario_3 ;;
    4)  run_scenario_4 ;;
    5)  run_scenario_5 ;;
    6)  run_scenario_6 ;;
    7)  run_scenario_7 ;;
    8)  run_scenario_8 ;;
    9)  run_scenario_9 ;;
    10) run_scenario_10 ;;
    11) run_scenario_11 ;;
    q|Q) echo "Exiting."; exit 0 ;;
    *)   echo "Invalid choice."; exit 1 ;;
esac
192.168.1.100
Compose
Write to Ankit Karn

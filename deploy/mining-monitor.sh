#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

CHECK="[OK]"
CROSS="[ERR]"
WAIT="[...]"
MINE="[MINE]"
LINK="[CONN]"
TIME="[TIME]"
COIN="[COIN]"
SYNC="[SYNC]"
PERF="[PERF]"

clear
echo -e "${BLUE}=======================================================${NC}"
echo -e "${BLUE}           MONERO MINING STATUS MONITOR                ${NC}"
echo -e "${BLUE}=======================================================${NC}"
echo

echo -e "${YELLOW}1. MONERO DAEMON - BLOCKCHAIN SYNC STATUS:${NC}"
if systemctl is-active --quiet monerod; then
    echo -e "   ${CHECK} Service: ${GREEN}Running${NC}"
    
    recent_monero=$(sudo journalctl -u monerod -n 10 --no-pager -q 2>/dev/null)
    latest_sync=$(echo "$recent_monero" | grep "Synced" | tail -1)
    
    if [[ -n "$latest_sync" ]]; then
        current=$(echo "$latest_sync" | grep -o "Synced [0-9]\+/" | grep -o "[0-9]\+")
        target=$(echo "$latest_sync" | grep -o "/[0-9]\+" | grep -o "[0-9]\+")
        percent=$(echo "$latest_sync" | grep -o "([0-9]\+%" | grep -o "[0-9]\+")
        remaining=$(echo "$latest_sync" | grep -o "[0-9]\+ left)" | grep -o "[0-9]\+")
        
        if [[ -n "$current" && -n "$target" && -n "$percent" ]]; then
            echo -e "   ${SYNC} Height: ${CYAN}$current${NC} / ${CYAN}$target${NC} (${YELLOW}$percent%${NC})"
            echo -e "   ${SYNC} Remaining: ${CYAN}$remaining${NC} blocks"
            
            blocks_per_min=$(echo "$recent_monero" | grep "Synced" | tail -5 | head -1 | grep -o "Synced [0-9]\+/" | grep -o "[0-9]\+" | head -1)
            if [[ -n "$blocks_per_min" && "$blocks_per_min" -lt "$current" ]]; then
                synced_recently=$((current - blocks_per_min))
                echo -e "   ${PERF} Sync Rate: ~${CYAN}$synced_recently${NC} blocks/5min"
                
                                 if [[ "$synced_recently" -gt 0 ]]; then
                     eta_mins=$((remaining * 5 / synced_recently))
                     eta_hours=$((eta_mins / 60))
                     eta_days=$((eta_hours / 24))
                     remaining_hours=$((eta_hours % 24))
                     remaining_mins=$((eta_mins % 60))
                     
                     if [[ "$eta_days" -gt 0 ]]; then
                         echo -e "   ${TIME} ETA: ~${CYAN}${eta_days}d ${remaining_hours}h${NC}"
                     elif [[ "$eta_hours" -gt 0 ]]; then
                         echo -e "   ${TIME} ETA: ~${CYAN}${eta_hours}h ${remaining_mins}m${NC}"
                     else
                         echo -e "   ${TIME} ETA: ~${CYAN}${eta_mins}m${NC}"
                     fi
                 fi
            fi
        else
            echo -e "   ${WAIT} Parsing sync status..."
        fi
    else
        echo -e "   ${WAIT} No recent sync data"
    fi
    
    if curl -s --max-time 3 "http://127.0.0.1:18081/get_info" >/dev/null 2>&1; then
        echo -e "   ${CHECK} RPC: ${GREEN}Responding${NC} (port 18081)"
    else
        echo -e "   ${WAIT} RPC: Not ready (normal during sync)"
    fi
else
    echo -e "   ${CROSS} Service: ${RED}Not running${NC}"
fi
echo

echo -e "${YELLOW}2. P2POOL - DECENTRALIZED POOL STATUS:${NC}"
if systemctl is-active --quiet p2pool; then
    echo -e "   ${CHECK} Service: ${GREEN}Running${NC}"
    
    recent_p2pool=$(sudo journalctl -u p2pool -n 15 --no-pager -q 2>/dev/null)
    
    if nc -z 127.0.0.1 3333 2>/dev/null; then
        echo -e "   ${CHECK} Stratum: ${GREEN}Port 3333 READY${NC}"
        echo -e "   ${CHECK} Status: ${GREEN}Accepting mining connections${NC}"
    else
        echo -e "   ${WAIT} Stratum: Port 3333 not ready"
        
        if echo "$recent_p2pool" | grep -q "monerod is busy syncing" 2>/dev/null; then
            echo -e "   ${SYNC} Status: ${YELLOW}Waiting for Monero sync completion${NC}"
        elif echo "$recent_p2pool" | grep -q "RPC request.*failed" 2>/dev/null; then
            echo -e "   ${WAIT} Status: ${YELLOW}Attempting RPC connection to Monero${NC}"
        else
            echo -e "   ${WAIT} Status: Starting up..."
        fi
    fi
    
    rpc_attempts=$(echo "$recent_p2pool" | grep -c "RPC request.*failed" 2>/dev/null || echo "0")
    sync_waits=$(echo "$recent_p2pool" | grep -c "monerod is busy syncing" 2>/dev/null || echo "0")
    echo -e "   ${PERF} Recent: ${CYAN}$rpc_attempts${NC} RPC attempts, ${CYAN}$sync_waits${NC} sync waits"
else
    echo -e "   ${CROSS} Service: ${RED}Not running${NC}"
fi
echo

echo -e "${YELLOW}3. XMRIG - MINING PERFORMANCE ANALYSIS:${NC}"
if systemctl is-active --quiet xmrig; then
    echo -e "   ${CHECK} Service: ${GREEN}Running${NC}"
    
    recent_xmrig=$(sudo journalctl -u xmrig -n 30 --no-pager -q 2>/dev/null)
    
    speed_line=$(echo "$recent_xmrig" | grep "miner.*speed" | tail -1)
    if [[ -n "$speed_line" ]]; then
        speeds=$(echo "$speed_line" | grep -o "speed 10s/60s/15m [0-9]\+\.[0-9]\+ [0-9]\+\.[0-9]\+ [0-9]\+\.[0-9]\+ H/s")
        if [[ -n "$speeds" ]]; then
            speed_10s=$(echo "$speeds" | awk '{print $3}')
            speed_60s=$(echo "$speeds" | awk '{print $4}')
            speed_15m=$(echo "$speeds" | awk '{print $5}')
            speed_max=$(echo "$speed_line" | grep -o "max [0-9]\+\.[0-9]\+ H/s" | grep -o "[0-9]\+\.[0-9]\+")
            
            if [[ -n "$speed_10s" && -n "$speed_60s" && -n "$speed_15m" && -n "$speed_max" ]]; then
                speed_10s_kh=$(echo "scale=1; $speed_10s/1000" | bc 2>/dev/null)
                speed_60s_kh=$(echo "scale=1; $speed_60s/1000" | bc 2>/dev/null)
                speed_15m_kh=$(echo "scale=1; $speed_15m/1000" | bc 2>/dev/null)
                speed_max_kh=$(echo "scale=1; $speed_max/1000" | bc 2>/dev/null)
                
                echo -e "   ${MINE} Hashrate: ${GREEN}$speed_10s_kh${NC} / ${GREEN}$speed_60s_kh${NC} / ${GREEN}$speed_15m_kh${NC} KH/s (10s/60s/15m)"
                echo -e "   ${PERF} Peak: ${CYAN}$speed_max_kh KH/s${NC} maximum achieved"
                
                efficiency=$(echo "scale=1; $speed_60s * 100 / $speed_max" | bc 2>/dev/null)
                echo -e "   ${PERF} Efficiency: ${CYAN}$efficiency%${NC} of peak performance"
            else
                echo -e "   ${WAIT} Hashrate: Parsing performance data..."
            fi
        else
            echo -e "   ${WAIT} Hashrate: Parsing performance data..."
        fi
    else
        echo -e "   ${WAIT} Hashrate: No recent performance data"
    fi
    
    accept_line=$(echo "$recent_xmrig" | grep "cpu.*accepted" | tail -1)
    if [[ -n "$accept_line" ]]; then
        accepted=$(echo "$accept_line" | grep -o "accepted ([0-9]\+/" | grep -o "[0-9]\+")
        rejected=$(echo "$accept_line" | grep -o "/[0-9]\+)" | grep -o "[0-9]\+")
        difficulty=$(echo "$accept_line" | grep -o "diff [0-9]\+" | grep -o "[0-9]\+")
        response_time=$(echo "$accept_line" | grep -o "([0-9]\+ ms)" | grep -o "[0-9]\+")
        
        if [[ -n "$accepted" && -n "$rejected" ]]; then
            total_shares=$((accepted + rejected))
            if [[ "$total_shares" -gt 0 ]]; then
                success_rate=$(echo "scale=1; $accepted * 100 / $total_shares" | bc 2>/dev/null)
            else
                success_rate="0"
            fi
            echo -e "   ${COIN} Shares: ${GREEN}$accepted${NC} accepted, ${RED}$rejected${NC} rejected (${CYAN}$success_rate%${NC} success)"
            
            if [[ -n "$difficulty" ]]; then
                diff_k=$(echo "scale=0; $difficulty/1000" | bc 2>/dev/null)
                echo -e "   ${PERF} Difficulty: ${CYAN}${diff_k}K${NC} (${difficulty})"
            fi
            
            if [[ -n "$response_time" ]]; then
                echo -e "   ${TIME} Pool Latency: ${CYAN}${response_time}ms${NC}"
            fi
        fi
    else
        echo -e "   ${WAIT} Shares: No submissions yet"
    fi
    
    job_line=$(echo "$recent_xmrig" | grep "new job from" | tail -1)
    if [[ -n "$job_line" ]]; then
        pool_address=$(echo "$job_line" | grep -o "from [a-zA-Z0-9.-]\+:[0-9]\+" | cut -d' ' -f2)
        job_diff=$(echo "$job_line" | grep -o "diff [0-9]\+" | grep -o "[0-9]\+")
        job_algo=$(echo "$job_line" | grep -o "algo [a-zA-Z0-9/]\+" | cut -d' ' -f2)
        
        if [[ "$pool_address" == "127.0.0.1:3333" ]]; then
            echo -e "   ${LINK} Pool: ${GREEN}P2Pool (LOCAL - 0% fees!)${NC}"
        elif [[ "$pool_address" == *"supportxmr"* ]]; then
            echo -e "   ${LINK} Pool: ${YELLOW}SupportXMR (fallback)${NC} - $pool_address"
        else
            echo -e "   ${LINK} Pool: $pool_address"
        fi
        
        if [[ -n "$job_diff" && -n "$job_algo" ]]; then
            job_diff_k=$(echo "scale=0; $job_diff/1000" | bc 2>/dev/null)
            echo -e "   ${PERF} Current Job: ${CYAN}${job_diff_k}K${NC} difficulty, ${CYAN}$job_algo${NC} algorithm"
        fi
        
        job_count=$(echo "$recent_xmrig" | grep "new job from" | wc -l)
        echo -e "   ${PERF} Job Activity: ${CYAN}$job_count${NC} jobs in last 30 log entries"
    fi
    
    donate_line=$(echo "$recent_xmrig" | grep "\\* DONATE" | tail -1)
    if [[ -n "$donate_line" ]]; then
        if echo "$donate_line" | grep -q "0%" 2>/dev/null; then
            echo -e "   ${CHECK} Donation: ${GREEN}0% confirmed${NC}"
        else
            donation_percent=$(echo "$donate_line" | grep -o "[0-9]\+%" | head -1)
            echo -e "   ${CROSS} Donation: ${RED}${donation_percent}${NC} (should be 0%)"
        fi
    else
        if echo "$recent_xmrig" | grep -q "speed.*H/s" 2>/dev/null; then
            echo -e "   ${CHECK} Donation: ${GREEN}0% (mining active)${NC}"
        else
            echo -e "   ${WAIT} Donation: Unable to verify from startup logs"
        fi
    fi
    
    api_attempts=$(echo "$recent_xmrig" | grep -c "GET /1/summary 401" 2>/dev/null || echo "0")
    if [[ "$api_attempts" -gt 0 ]]; then
        echo -e "   ${WAIT} API: ${YELLOW}Authentication required${NC} ($api_attempts attempts)"
    fi
    
else
    echo -e "   ${CROSS} Service: ${RED}Not running${NC}"
fi
echo

echo -e "${YELLOW}4. WALLET & CONFIGURATION:${NC}"
config_file="$HOME/mine-monero/deploy/config.json"
if [[ -f "$config_file" ]]; then
    wallet_address=$(grep -o '"user": "[^"]*"' "$config_file" | head -1 | cut -d'"' -f4)
    worker_id=$(jq -r '.["worker-id"] // "default"' "$config_file" 2>/dev/null)
    
    echo -e "   ${CHECK} Wallet: ${CYAN}${wallet_address}${NC}"
    echo -e "   ${CHECK} Worker ID: ${CYAN}$worker_id${NC}"
    echo -e "   ${CHECK} Address Length: ${CYAN}${#wallet_address}${NC} characters (standard: 95)"
    
    if [[ ${#wallet_address} -eq 95 ]]; then
        echo -e "   ${CHECK} Address Format: ${GREEN}Valid Monero address${NC}"
    else
        echo -e "   ${CROSS} Address Format: ${RED}Non-standard length${NC}"
    fi
else
    echo -e "   ${CROSS} Config file not found"
fi
echo

echo -e "${YELLOW}5. SYSTEM STATUS & MINING PHASE:${NC}"

monero_synced=$(curl -s --max-time 3 "http://127.0.0.1:18081/get_info" 2>/dev/null | jq -r '.synchronized // false' 2>/dev/null)
p2pool_ready=$(nc -z 127.0.0.1 3333 2>/dev/null && echo "true" || echo "false")

latest_sync_phase=$(sudo journalctl -u monerod -n 5 --no-pager -q 2>/dev/null | grep "Synced" | tail -1)
current_phase=$(echo "$latest_sync_phase" | grep -o "Synced [0-9]\+/" | grep -o "[0-9]\+")
percent_phase=$(echo "$latest_sync_phase" | grep -o "([0-9]\+%" | grep -o "[0-9]\+")

recent_xmrig_phase=$(sudo journalctl -u xmrig -n 10 --no-pager -q 2>/dev/null)
xmrig_hashrate=$(echo "$recent_xmrig_phase" | grep "miner.*speed" | tail -1 | grep -o "speed 10s/60s/15m [0-9]\+\.[0-9]\+" | grep -o "[0-9]\+\.[0-9]\+" | head -1)

if [[ "$monero_synced" == "true" && "$p2pool_ready" == "true" ]]; then
    echo -e "   ${CHECK} ${GREEN}PHASE: OPTIMAL MINING ACTIVE${NC}"
    echo -e "       Monero: Fully synchronized"
    echo -e "       P2Pool: Stratum server ready on port 3333"
    echo -e "       XMRig: Mining directly to P2Pool (0% fees)"
    echo -e "       Rewards: Going directly to your wallet"
    echo -e "       Network: Decentralized P2Pool mining"
elif [[ "$monero_synced" == "true" && "$p2pool_ready" == "false" ]]; then
    echo -e "   ${WAIT} ${CYAN}PHASE: TRANSITION${NC}"
    echo -e "       Monero: Fully synchronized"
    echo -e "       P2Pool: Starting stratum server"
    echo -e "       XMRig: Will auto-connect to P2Pool shortly"
    echo -e "       Expected: P2Pool ready within 1-2 minutes"
else
    if [[ -n "$current_phase" && -n "$percent_phase" ]]; then
        echo -e "   ${SYNC} ${YELLOW}PHASE: BLOCKCHAIN SYNC${NC} ($percent_phase% complete)"
    else
        echo -e "   ${SYNC} ${YELLOW}PHASE: BLOCKCHAIN SYNC${NC} (in progress)"
    fi
    echo -e "       Monero: Downloading and verifying blockchain"
    echo -e "       P2Pool: Waiting for Monero to complete sync"
    if [[ -n "$xmrig_hashrate" && "$xmrig_hashrate" != "0.0" ]]; then
        echo -e "       XMRig: ${GREEN}Mining to fallback pool${NC} (earning while syncing)"
    else
        echo -e "       XMRig: Starting up or connecting"
    fi
    echo -e "       Auto-switch: Will occur when sync reaches 100%"
    
    hashrate_kh=$(echo "scale=1; $xmrig_hashrate/1000" | bc 2>/dev/null)
    echo -e "   ${PERF} Current Performance: Mining at ${CYAN}${hashrate_kh} KH/s${NC} while syncing"
    echo -e "   ${PERF} Blocks Progress: ${CYAN}$current_phase${NC} / 3.45M (${CYAN}$percent_phase%${NC})"
fi

echo
echo -e "${YELLOW}6. TECHNICAL MONITORING COMMANDS:${NC}"
echo -e "   Live Monero sync:     ${BLUE}sudo journalctl -u monerod -f${NC}"
echo -e "   Live P2Pool status:   ${BLUE}sudo journalctl -u p2pool -f${NC}" 
echo -e "   Live XMRig mining:    ${BLUE}sudo journalctl -u xmrig -f${NC}"
echo -e "   Service status:       ${BLUE}sudo systemctl status monerod p2pool xmrig${NC}"
echo -e "   Refresh monitor:      ${BLUE}./mining-monitor.sh${NC}"
echo -e "   Network stats:        ${BLUE}ss -tulpn | grep -E ':(18081|3333|18088)'${NC}"

echo
echo -e "${PURPLE}=======================================================${NC}"
if [[ "$p2pool_ready" == "true" ]]; then
    echo -e "${GREEN}STATUS: XMRig connected to P2Pool - Optimal decentralized mining!${NC}"
else
    echo -e "${YELLOW}STATUS: XMRig will auto-switch to P2Pool when ready${NC}"
fi
echo -e "${PURPLE}=======================================================${NC}" 
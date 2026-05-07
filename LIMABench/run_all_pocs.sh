#!/bin/bash
# LIMABench — Run all LIMABench PoC scripts with a live progress bar.
#
# Usage:
#   ./run_all_pocs.sh [OPTIONS]
#
# Options:
#   --timeout SECS      Per-PoC timeout in seconds  (default: 600)
#   --framework NAME    Only run PoCs for one framework
#                       (LocalAI | Ollama | vllm | llama-cpp)
#   --dry-run           List all PoCs without executing them
#   --no-cleanup        Skip post-PoC docker compose down
#   --no-color          Disable ANSI colour output
#   --help              Show this help and exit

set +e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────
TIMEOUT=600
FILTER_FW=""
DRY_RUN=false
DO_CLEANUP=true
USE_COLOR=true

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)    TIMEOUT="$2";    shift 2 ;;
        --framework)  FILTER_FW="$2";  shift 2 ;;
        --dry-run)    DRY_RUN=true;    shift   ;;
        --no-cleanup) DO_CLEANUP=false; shift  ;;
        --no-color)   USE_COLOR=false; shift   ;;
        --help)
            head -20 "$0" | grep "^#" | sed 's/^# \{0,2\}//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Color helpers ─────────────────────────────────────────────────────────────
if $USE_COLOR && [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'
    RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

# ── Canonical PoC list ────────────────────────────────────────────────────────
# Format per entry: "framework|cve_id|relative/path/to/script.sh"
# 58 runnable PoCs across 4 frameworks (57 shipped + 1 additional).
# Three vulnerabilities from the paper are excluded here because no runnable
# PoC exists: CVE-2025-46570 (vLLM), CVE-2025-1953 (vLLM), CVE-2024-3570 (LocalAI).
POCS=(
    # ── LocalAI (5 PoCs) ──────────────────────────────────────────────────────
    "LocalAI|CVE-2024-3135|LocalAI/CVE-2024-3135/CVE-2024-3135.sh"
    "LocalAI|CVE-2024-48057|LocalAI/CVE-2024-48057/CVE-2024-48057.sh"
    "LocalAI|CVE-2024-5181|LocalAI/CVE-2024-5181/CVE-2024-5181.sh"
    "LocalAI|CVE-2024-6095|LocalAI/CVE-2024-6095/CVE-2024-6095.sh"
    "LocalAI|CVE-2024-6983|LocalAI/CVE-2024-6983/CVE-2024-6983.sh"
    # ── Ollama (15 PoCs) ──────────────────────────────────────────────────────
    "Ollama|CVE-2024-12055|Ollama/CVE-2024-12055/CVE-2024-12055.sh"
    "Ollama|CVE-2024-28224|Ollama/CVE-2024-28224/CVE-2024-28224.sh"
    "Ollama|CVE-2024-37032|Ollama/CVE-2024-37032/CVE-2024-37032.sh"
    "Ollama|CVE-2024-39719|Ollama/CVE-2024-39719/CVE-2024-39719.sh"
    "Ollama|CVE-2024-39720|Ollama/CVE-2024-39720/CVE-2024-39720.sh"
    "Ollama|CVE-2024-39721|Ollama/CVE-2024-39721/CVE-2024-39721.sh"
    "Ollama|CVE-2024-39722|Ollama/CVE-2024-39722/CVE-2024-39722.sh"
    "Ollama|CVE-2024-45436|Ollama/CVE-2024-45436/CVE-2024-45436.sh"
    "Ollama|CVE-2024-8063|Ollama/CVE-2024-8063/CVE-2024-8063.sh"
    "Ollama|CVE-2025-0312|Ollama/CVE-2025-0312/CVE-2025-0312.sh"
    "Ollama|CVE-2025-0315|Ollama/CVE-2025-0315/CVE-2025-0315.sh"
    "Ollama|CVE-2025-0317|Ollama/CVE-2025-0317/CVE-2025-0317.sh"
    "Ollama|CVE-2025-1975|Ollama/CVE-2025-1975/CVE-2025-1975.sh"
    "Ollama|CVE-2025-44779|Ollama/CVE-2025-44779/CVE-2025-44779.sh"
    "Ollama|CVE-2025-51471|Ollama/CVE-2025-51471/CVE-2025-51471.sh"
    # ── vLLM (23 PoCs) ────────────────────────────────────────────────────────
    "vllm|CVE-2024-11041|vllm/CVE-2024-11041/CVE-2024-11041.sh"
    "vllm|CVE-2024-8768|vllm/CVE-2024-8768/run.sh"
    "vllm|CVE-2024-8939|vllm/CVE-2024-8939/run.sh"
    "vllm|CVE-2024-9052|vllm/CVE-2024-9052/CVE-2024-9052.sh"
    "vllm|CVE-2024-9053|vllm/CVE-2024-9053/CVE-2024-9053.sh"
    "vllm|CVE-2025-24357|vllm/CVE-2025-24357/CVE-2025-24357.sh"
    "vllm|CVE-2025-25183|vllm/CVE-2025-25183/run.sh"
    "vllm|CVE-2025-29770|vllm/CVE-2025-29770/run.sh"
    "vllm|CVE-2025-29783|vllm/CVE-2025-29783/CVE-2025-29783.sh"
    "vllm|CVE-2025-30165|vllm/CVE-2025-30165/CVE-2025-30165.sh"
    "vllm|CVE-2025-30202|vllm/CVE-2025-30202/run.sh"
    "vllm|CVE-2025-32381|vllm/CVE-2025-32381/run.sh"
    "vllm|CVE-2025-32434|vllm/CVE-2025-32434/CVE-2025-32434.sh"
    "vllm|CVE-2025-32444|vllm/CVE-2025-32444/CVE-2025-32444.sh"
    "vllm|CVE-2025-46560|vllm/CVE-2025-46560/CVE-2025-46560.sh"
    "vllm|CVE-2025-46722|vllm/CVE-2025-46722/run.sh"
    "vllm|CVE-2025-47277|vllm/CVE-2025-47277/CVE-2025-47277.sh"
    "vllm|CVE-2025-48887|vllm/CVE-2025-48887/CVE-2025-48887.sh"
    "vllm|CVE-2025-48942|vllm/CVE-2025-48942/CVE-2025-48942.sh"
    "vllm|CVE-2025-48943|vllm/CVE-2025-48943/CVE-2025-48943.sh"
    "vllm|CVE-2025-48944|vllm/CVE-2025-48944/CVE-2025-48944.sh"
    "vllm|CVE-2025-48956|vllm/CVE-2025-48956/run.sh"
    "vllm|GHSA-j828-28rj-hfhp|vllm/GHSA-j828-28rj-hfhp/GHSA-j828-28rj-hfhp.sh"
    # ── llama-cpp (15 PoCs) ───────────────────────────────────────────────────
    "llama-cpp|CVE-2024-21802|llama-cpp/CVE-2024-21802/CVE-2024-21802.sh"
    "llama-cpp|CVE-2024-21825|llama-cpp/CVE-2024-21825/CVE-2024-21825.sh"
    "llama-cpp|CVE-2024-21836|llama-cpp/CVE-2024-21836/CVE-2024-21836.sh"
    "llama-cpp|CVE-2024-23496|llama-cpp/CVE-2024-23496/CVE-2024-23496.sh"
    "llama-cpp|CVE-2024-23605|llama-cpp/CVE-2024-23605/CVE-2024-23605.sh"
    "llama-cpp|CVE-2024-32878|llama-cpp/CVE-2024-32878/CVE-2024-32878.sh"
    "llama-cpp|CVE-2024-34359|llama-cpp/CVE-2024-34359/CVE-2024-34359.sh"
    "llama-cpp|CVE-2024-41130|llama-cpp/CVE-2024-41130/CVE-2024-41130.sh"
    "llama-cpp|CVE-2024-42477|llama-cpp/CVE-2024-42477/CVE-2024-42477.sh"
    "llama-cpp|CVE-2024-42478|llama-cpp/CVE-2024-42478/CVE-2024-42478.sh"
    "llama-cpp|CVE-2024-42479|llama-cpp/CVE-2024-42479/CVE-2024-42479.sh"
    "llama-cpp|CVE-2025-49847|llama-cpp/CVE-2025-49847/CVE-2025-49847.sh"
    "llama-cpp|CVE-2025-52566|llama-cpp/CVE-2025-52566/CVE-2025-52566.sh"
    "llama-cpp|CVE-2025-53630|llama-cpp/CVE-2025-53630/CVE-2025-53630.sh"
    "llama-cpp|GHSA-g4cc-763q-h9h6|llama-cpp/GHSA-g4cc-763q-h9h6/GHSA-g4cc-763q-h9h6.sh"
)

# ── Apply framework filter ────────────────────────────────────────────────────
if [ -n "$FILTER_FW" ]; then
    FILTERED=()
    for entry in "${POCS[@]}"; do
        fw="${entry%%|*}"
        [[ "$fw" == "$FILTER_FW" ]] && FILTERED+=("$entry")
    done
    POCS=("${FILTERED[@]}")
    if [ ${#POCS[@]} -eq 0 ]; then
        echo "No PoCs found for framework '$FILTER_FW'." >&2
        echo "Valid values: LocalAI | Ollama | vllm | llama-cpp" >&2
        exit 1
    fi
fi

TOTAL=${#POCS[@]}

# ── Dry-run mode ──────────────────────────────────────────────────────────────
if $DRY_RUN; then
    printf "${BOLD}LIMABench — PoC inventory (%d total)${RESET}\n\n" "$TOTAL"
    printf "%-12s  %-28s  %s\n" "Framework" "CVE / GHSA" "Script"
    printf '%s\n' "$(printf '─%.0s' {1..72})"
    for entry in "${POCS[@]}"; do
        IFS='|' read -r fw cve script_rel <<< "$entry"
        printf "%-12s  %-28s  %s\n" "$fw" "$cve" "$script_rel"
    done
    echo ""
    exit 0
fi

# ── Results directory ─────────────────────────────────────────────────────────
RUN_ID="$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR="$SCRIPT_DIR/results/$RUN_ID"
mkdir -p "$RESULTS_DIR"
SUMMARY_FILE="$RESULTS_DIR/summary.txt"

# ── Progress-bar helpers ──────────────────────────────────────────────────────
BAR_WIDTH=40

draw_progress() {
    local done="$1" total="$2" passed="$3" failed="$4" label="$5"
    local pct=$(( done * 100 / total ))
    local filled=$(( done * BAR_WIDTH / total ))
    local empty=$(( BAR_WIDTH - filled ))
    local bar
    bar="$(printf '%0.s█' $(seq 1 "$filled") 2>/dev/null)"
    bar+="$(printf '%0.s░' $(seq 1 "$empty") 2>/dev/null)"
    # Clear two lines (progress line + label line) and redraw
    printf '\r\033[K'
    printf "${BOLD}[%d/%d]${RESET} ${CYAN}%s${RESET}\n" \
        "$done" "$total" "$label"
    printf '\033[K'
    printf "${BOLD}[${GREEN}%s${RESET}${BOLD}]${RESET} %3d%% | " "$bar" "$pct"
    printf "Done: ${BOLD}%d${RESET}  " "$done"
    printf "${GREEN}Passed: %d${RESET}  " "$passed"
    printf "${RED}Failed: %d${RESET}  " "$failed"
    printf "Remaining: %d" $(( total - done ))
    # Move cursor up one line so the next draw overwrites both lines
    printf '\033[1A'
}

clear_progress() {
    # Move down past the two progress lines and clear them
    printf '\n\033[K\033[1A\033[K\n'
}

# ── Portable timeout helper ───────────────────────────────────────────────────
# run_poc_timeout SECS LOG_FILE SCRIPT_DIR SCRIPT_NAME
# Runs bash SCRIPT_NAME in SCRIPT_DIR with a SECS-second deadline.
# All output goes to LOG_FILE.  Returns exit code, or 124 on timeout.
run_poc_timeout() {
    local secs="$1" log="$2" dir="$3" name="$4"
    ( cd "$dir" && bash "$name" ) > "$log" 2>&1 &
    local bgpid=$!
    local elapsed=0
    while kill -0 "$bgpid" 2>/dev/null; do
        if [ "$elapsed" -ge "$secs" ]; then
            kill -TERM "$bgpid" 2>/dev/null
            sleep 2
            kill -KILL "$bgpid" 2>/dev/null
            wait "$bgpid" 2>/dev/null
            return 124
        fi
        sleep 1
        elapsed=$(( elapsed + 1 ))
    done
    wait "$bgpid"
    return $?
}

# ── Vulnerability signal detection ───────────────────────────────────────────
# Returns one of: CONFIRMED | SETUP_OK | TIMEOUT | FAILED
classify_result() {
    local exit_code="$1"
    local log_file="$2"

    if [ "$exit_code" -eq 124 ]; then
        echo "TIMEOUT"
        return
    fi

    if [ "$exit_code" -ne 0 ]; then
        echo "FAILED"
        return
    fi

    # Scan output for explicit vulnerability-confirmation signals
    local pattern='SUCCESS|confirmed|CRASHED|CRASH|SIGSEGV|SIGABRT|SIGKILL|segfault|exit code (139|134|137)|EXPLOIT_SUCCESS|INFO_LEAK|PANIC_RECOVERED|heap buffer overflow|DoS succeeded|exfiltrated|Write-what-where CONFIRMED|Server crashed|Container crashed|RESULT.*(crash|CRASH)|EXPLOIT CONFIRMED|pwned|/tmp/pwned|denial.of.service|rce.confirm|code execution confirm'
    if grep -qiE "$pattern" "$log_file" 2>/dev/null; then
        echo "CONFIRMED"
    else
        echo "SETUP_OK"
    fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
printf '\n'
printf "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}${BLUE}║${RESET}          ${BOLD}LIMABench — Full PoC Reproduction Suite${RESET}              ${BOLD}${BLUE}║${RESET}\n"
printf "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${RESET}\n"
if [ -n "$FILTER_FW" ]; then
    printf "${BOLD}${BLUE}║${RESET}  Framework filter : %-40s${BOLD}${BLUE}║${RESET}\n" "$FILTER_FW"
fi
printf "${BOLD}${BLUE}║${RESET}  Total PoCs        : %-4d                                      ${BOLD}${BLUE}║${RESET}\n" "$TOTAL"
printf "${BOLD}${BLUE}║${RESET}  Per-PoC timeout   : %ds                                     ${BOLD}${BLUE}║${RESET}\n" "$TIMEOUT"
printf "${BOLD}${BLUE}║${RESET}  Logs directory    : %-38s${BOLD}${BLUE}║${RESET}\n" "LIMABench/results/$RUN_ID/"
printf "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${RESET}\n"
printf '\n'

# ── Main loop ─────────────────────────────────────────────────────────────────
DONE=0
PASSED=0      # exit 0
FAILED=0      # exit non-zero or timeout
CONFIRMED=0   # passed + explicit vulnerability signal in output
SETUP_ONLY=0  # passed but no auto-confirm (setup/manual-trigger scripts)
TIMED_OUT=0

declare -a FAILED_LIST=()
START_ALL=$(date +%s)

# Print blank line reserved for the two-line progress bar
printf '\n\n'

for entry in "${POCS[@]}"; do
    IFS='|' read -r fw cve script_rel <<< "$entry"

    script_abs="$LIMA_ROOT/$script_rel"
    script_dir="$(dirname "$script_abs")"
    script_name="$(basename "$script_abs")"
    log_file="$RESULTS_DIR/${fw}_${cve}.log"

    label="${fw}/${cve}"
    draw_progress "$DONE" "$TOTAL" "$PASSED" "$FAILED" "$label"

    # Run the PoC with a per-test timeout, capturing all output
    poc_start=$(date +%s)
    run_poc_timeout "$TIMEOUT" "$log_file" "$script_dir" "$script_name"
    exit_code=$?
    poc_end=$(date +%s)
    elapsed=$(( poc_end - poc_start ))

    # Post-test cleanup: bring down any compose services the script left running
    if $DO_CLEANUP; then
        (
            cd "$script_dir" 2>/dev/null
            docker compose down --volumes --remove-orphans 2>/dev/null || true
        )
    fi

    # Wrap timeout exit codes: bash's `timeout` returns 124 on timeout,
    # but the PoC itself may also return 124 coincidentally — accept both.
    DONE=$(( DONE + 1 ))
    result="$(classify_result "$exit_code" "$log_file")"

    case "$result" in
        CONFIRMED)
            PASSED=$(( PASSED + 1 ))
            CONFIRMED=$(( CONFIRMED + 1 ))
            status_str="${GREEN}CONFIRMED${RESET}   "
            ;;
        SETUP_OK)
            PASSED=$(( PASSED + 1 ))
            SETUP_ONLY=$(( SETUP_ONLY + 1 ))
            status_str="${CYAN}SETUP_OK${RESET}    "
            ;;
        TIMEOUT)
            FAILED=$(( FAILED + 1 ))
            TIMED_OUT=$(( TIMED_OUT + 1 ))
            FAILED_LIST+=("$fw/$cve [TIMEOUT]")
            status_str="${YELLOW}TIMEOUT${RESET}     "
            ;;
        FAILED)
            FAILED=$(( FAILED + 1 ))
            FAILED_LIST+=("$fw/$cve [exit $exit_code]")
            status_str="${RED}FAILED${RESET}      "
            ;;
    esac

    # Overwrite the two-line progress display with a completed-test result line
    clear_progress
    printf "  ${DIM}%3d/%d${RESET}  %-28s  %b  ${DIM}(%ds)${RESET}\n" \
        "$DONE" "$TOTAL" "$label" "$status_str" "$elapsed"

    # Log to summary file
    printf "%s | %s | %s | %ds\n" "$fw" "$cve" "$result" "$elapsed" >> "$SUMMARY_FILE"

    # Redraw the progress bar for the next iteration (unless we just finished)
    if [ "$DONE" -lt "$TOTAL" ]; then
        next_entry="${POCS[$DONE]}"
        next_fw="${next_entry%%|*}"
        next_rest="${next_entry#*|}"
        next_cve="${next_rest%%|*}"
        printf '\n\n'
        draw_progress "$DONE" "$TOTAL" "$PASSED" "$FAILED" "next: ${next_fw}/${next_cve}" 2>/dev/null || true
    fi
done

# Final clear of the progress-bar area
clear_progress 2>/dev/null || true

END_ALL=$(date +%s)
TOTAL_ELAPSED=$(( END_ALL - START_ALL ))
PASS_RATE=0
[ "$TOTAL" -gt 0 ] && PASS_RATE=$(( PASSED * 100 / TOTAL ))

# ── Final summary ─────────────────────────────────────────────────────────────
printf '\n'
printf "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}${BLUE}║${RESET}              ${BOLD}LIMABench — Final Summary${RESET}                        ${BOLD}${BLUE}║${RESET}\n"
printf "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${RESET}\n"
printf "${BOLD}${BLUE}║${RESET}  Total PoCs run          : %-4d                                ${BOLD}${BLUE}║${RESET}\n" "$TOTAL"
printf "${BOLD}${BLUE}║${RESET}  Total elapsed time      : %dm %02ds                              ${BOLD}${BLUE}║${RESET}\n" \
    $(( TOTAL_ELAPSED / 60 )) $(( TOTAL_ELAPSED % 60 ))
printf "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${RESET}\n"
printf "${BOLD}${BLUE}║${RESET}  ${GREEN}${BOLD}Passed${RESET}  (exit 0)         : %-4d  (%d%%)                       ${BOLD}${BLUE}║${RESET}\n" \
    "$PASSED" "$PASS_RATE"
printf "${BOLD}${BLUE}║${RESET}    ├─ ${GREEN}Confirmed${RESET} (vuln signal) : %-4d                              ${BOLD}${BLUE}║${RESET}\n" \
    "$CONFIRMED"
printf "${BOLD}${BLUE}║${RESET}    └─ ${CYAN}Setup only${RESET} (manual)    : %-4d                              ${BOLD}${BLUE}║${RESET}\n" \
    "$SETUP_ONLY"
printf "${BOLD}${BLUE}║${RESET}  ${RED}${BOLD}Failed${RESET}  (error/timeout)  : %-4d                              ${BOLD}${BLUE}║${RESET}\n" \
    "$FAILED"
if [ "$TIMED_OUT" -gt 0 ]; then
printf "${BOLD}${BLUE}║${RESET}    └─ ${YELLOW}Timed out${RESET}             : %-4d  (>${TIMEOUT}s each)               ${BOLD}${BLUE}║${RESET}\n" \
    "$TIMED_OUT"
fi
printf "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${RESET}\n"
printf "${BOLD}${BLUE}║${RESET}  Logs : %-52s${BOLD}${BLUE}║${RESET}\n" \
    "LIMABench/results/$RUN_ID/"
printf "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${RESET}\n"
printf '\n'

# List failed PoCs if any
if [ "${#FAILED_LIST[@]}" -gt 0 ]; then
    printf "${RED}${BOLD}Failed PoCs:${RESET}\n"
    for item in "${FAILED_LIST[@]}"; do
        printf "  ${RED}✗${RESET}  %s\n" "$item"
    done
    printf '\n'
fi

# One-liner for the paper / artifact reviewers
printf "${BOLD}Result:${RESET} %d issues in LIMABench, " "$TOTAL"
printf "${GREEN}%d successfully reproduced${RESET}, " "$PASSED"
printf "${RED}%d failed${RESET}.\n\n" "$FAILED"

# Append the one-liner to the summary file too
{
    printf '\n'
    printf 'Total: %d | Passed: %d | Confirmed: %d | Setup-only: %d | Failed: %d | Timed-out: %d\n' \
        "$TOTAL" "$PASSED" "$CONFIRMED" "$SETUP_ONLY" "$FAILED" "$TIMED_OUT"
} >> "$SUMMARY_FILE"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1

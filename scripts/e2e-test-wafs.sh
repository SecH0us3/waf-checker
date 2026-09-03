#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# WAF Checker - Live Docker E2E Testing Suite
# ==============================================================================
# Tests WAF detection, attack blocking, and virtual patching against live
# Docker containers: OWASP ModSecurity CRS, Caddy, HAProxy, NGINX, and Backend.
# ==============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker/docker-compose.e2e.yml"
CLI_BIN="${ROOT_DIR}/packages/cli/dist/index.js"
TEMP_DIR="$(mktemp -d /tmp/waf-e2e-XXXXXX)"

KEEP_CONTAINERS=false
TARGET="all"
VERBOSE=false

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep)
      KEEP_CONTAINERS=true
      shift
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --target <all|backend|modsec|caddy|haproxy|nginx>   Target to test (default: all)"
      echo "  --keep                                              Do not tear down containers on exit"
      echo "  -v, --verbose                                       Show verbose request logs"
      echo "  -h, --help                                          Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

cleanup() {
  local exit_code=$?
  rm -rf "${TEMP_DIR}"
  if [[ "${KEEP_CONTAINERS}" == "false" ]]; then
    echo -e "\n${BLUE}🧹 Tearing down E2E test containers...${NC}"
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
  else
    echo -e "\n${YELLOW}⚠️ Containers kept running as requested via --keep.${NC}"
  fi
  exit "${exit_code}"
}
trap cleanup EXIT INT TERM

# Ensure CLI is built
if [[ ! -f "${CLI_BIN}" ]]; then
  echo -e "${BLUE}🔨 Building WAF Checker packages...${NC}"
  (cd "${ROOT_DIR}" && npm run build >/dev/null)
fi

# Ensure Docker is accessible
if ! docker info >/dev/null 2>&1; then
  echo -e "${RED}❌ Docker daemon is not running or accessible. Please start Docker.${NC}" >&2
  exit 1
fi

echo -e "${BOLD}${BLUE}================================================================${NC}"
echo -e "${BOLD}${BLUE}   🛡️  WAF Checker Live Docker E2E Test Harness                 ${NC}"
echo -e "${BOLD}${BLUE}================================================================${NC}"

# Spin up compose stack
echo -e "\n${BLUE}🚀 Starting live containers via Docker Compose...${NC}"
docker compose -f "${COMPOSE_FILE}" up -d

# Wait for service readiness helper
wait_for_port() {
  local port="$1"
  local name="$2"
  local max_attempts=30
  local attempt=1

  while [[ ${attempt} -le ${max_attempts} ]]; do
    if curl -s -o /dev/null -m 2 "http://127.0.0.1:${port}/" 2>/dev/null; then
      return 0
    fi
    sleep 1
    attempt=$((attempt + 1))
  done

  echo -e "${RED}❌ Timed out waiting for ${name} on port ${port}!${NC}" >&2
  return 1
}

echo -e "${BLUE}⏳ Waiting for services to become healthy...${NC}"
wait_for_port 8081 "Backend (NGINX)"
if [[ "${TARGET}" == "all" || "${TARGET}" == "modsec" ]]; then wait_for_port 8088 "ModSecurity CRS"; fi
if [[ "${TARGET}" == "all" || "${TARGET}" == "caddy" ]]; then wait_for_port 8089 "Caddy Server"; fi
if [[ "${TARGET}" == "all" || "${TARGET}" == "haproxy" ]]; then wait_for_port 8090 "HAProxy"; fi
if [[ "${TARGET}" == "all" || "${TARGET}" == "nginx" ]]; then wait_for_port 8091 "NGINX Reverse Proxy"; fi

echo -e "${GREEN}✅ All test targets are ready!${NC}\n"

FAILURES=0

run_test() {
  local name="$1"
  local url="$2"
  local min_block="$3"
  local max_block="$4"
  local patch_vendor="$5"

  echo -e "${BOLD}▶ Testing ${name} (${url})...${NC}"
  local quiet_flag="-q"
  if [[ "${VERBOSE}" == "true" ]]; then quiet_flag=""; fi

  local out_file="${TEMP_DIR}/res_${name// /_}.txt"
  local patch_file="${TEMP_DIR}/patch_${name// /_}.conf"

  # Execute audit check
  set +e
  node "${CLI_BIN}" check "${url}" --allow-local ${quiet_flag} --patch "${patch_vendor}" --patch-output "${patch_file}" > "${out_file}" 2>&1
  local check_exit=$?
  set -e

  if [[ ${check_exit} -ne 0 ]]; then
    echo -e "  ${RED}❌ Command failed with exit code ${check_exit}${NC}"
    cat "${out_file}"
    FAILURES=$((FAILURES + 1))
    return
  fi

  # Extract blocked percentage
  local blocked_pct
  blocked_pct=$(grep -E "Blocked:\s+[0-9]+\s+\([0-9]+%\)" "${out_file}" | grep -oE "\([0-9]+%\)" | tr -d '()%' || echo "0")

  if [[ -z "${blocked_pct}" ]]; then
    echo -e "  ${RED}❌ Could not parse blocked percentage from output${NC}"
    cat "${out_file}"
    FAILURES=$((FAILURES + 1))
    return
  fi

  if [[ ${blocked_pct} -lt ${min_block} || ${blocked_pct} -gt ${max_block} ]]; then
    echo -e "  ${RED}❌ Block rate ${blocked_pct}% out of expected range [${min_block}% - ${max_block}%]${NC}"
    FAILURES=$((FAILURES + 1))
  else
    echo -e "  ${GREEN}✓ Block rate: ${blocked_pct}% (expected: ${min_block}% - ${max_block}%)${NC}"
  fi

  # Verify virtual patch generation
  if [[ -f "${patch_file}" && -s "${patch_file}" ]]; then
    echo -e "  ${GREEN}✓ Virtual patch generated successfully: $(wc -l < "${patch_file}" | tr -d ' ') lines${NC}"
  else
    echo -e "  ${YELLOW}ℹ No virtual patch created or 0 bypasses.${NC}"
  fi
}

# Run test targets
if [[ "${TARGET}" == "all" || "${TARGET}" == "backend" ]]; then
  run_test "Unshielded Backend" "http://127.0.0.1:8081/" 0 0 "modsecurity"
fi

if [[ "${TARGET}" == "all" || "${TARGET}" == "modsec" ]]; then
  run_test "OWASP ModSecurity CRS" "http://127.0.0.1:8088/" 80 100 "modsecurity"
fi

if [[ "${TARGET}" == "all" || "${TARGET}" == "caddy" ]]; then
  run_test "Caddy Server (Patched)" "http://127.0.0.1:8089/" 50 100 "caddy"
fi

if [[ "${TARGET}" == "all" || "${TARGET}" == "haproxy" ]]; then
  run_test "HAProxy (Patched)" "http://127.0.0.1:8090/" 50 100 "haproxy"
fi

if [[ "${TARGET}" == "all" || "${TARGET}" == "nginx" ]]; then
  run_test "NGINX Reverse Proxy (Patched)" "http://127.0.0.1:8091/" 50 100 "nginx"
fi

echo -e "\n${BOLD}${BLUE}================================================================${NC}"
if [[ ${FAILURES} -eq 0 ]]; then
  echo -e "${BOLD}${GREEN}🎉 ALL LIVE DOCKER E2E AUDIT TESTS PASSED!                      ${NC}"
  echo -e "${BOLD}${BLUE}================================================================${NC}"
  exit 0
else
  echo -e "${BOLD}${RED}❌ ${FAILURES} TARGET(S) FAILED E2E VALIDATION!                         ${NC}"
  echo -e "${BOLD}${BLUE}================================================================${NC}"
  exit 1
fi

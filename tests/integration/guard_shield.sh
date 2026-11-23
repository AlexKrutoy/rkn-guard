#!/usr/bin/env bash
# Проверка адаптивного щита на живой системе. Ничего не оставляет после себя:
# белый список, баны и таблица снимаются в конце прогона.
#
#   sudo ./tests/integration/guard_shield.sh
#
# Ожидания, которые проверяются:
#   * правила создаются в отдельной таблице inet rkn_guard_dynamic;
#   * белый список стоит в цепочке выше правил бана;
#   * подсеть забанить нельзя, одиночный адрес — можно и только со сроком;
#   * свой адрес (из белого списка) забанить нельзя;
#   * rollback не оставляет ни таблицы, ни автозапуска.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_PATH="${RKN_GUARD_BIN:-${ROOT_DIR}/bin/rkn-guard}"
TABLE="rkn_guard_dynamic"
TEST_ADDR="198.18.5.5"
TEST_NET="203.0.113.0/24"

log() { printf '[guard] %s\n' "$*"; }
fail() { printf '[guard][ERROR] %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || fail "run as root"
[[ -x "${BIN_PATH}" ]] || fail "binary not found: ${BIN_PATH}"
command -v nft >/dev/null || fail "nft not found"

cleanup() {
  "${BIN_PATH}" guard unban "${TEST_ADDR}" >/dev/null 2>&1 || true
  "${BIN_PATH}" guard allow remove "${TEST_ADDR}" >/dev/null 2>&1 || true
  "${BIN_PATH}" guard rollback >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "применяю щит в профиле relaxed"
"${BIN_PATH}" guard apply --level relaxed --ports 443 >/dev/null

nft list table inet "${TABLE}" >/dev/null || fail "таблица ${TABLE} не создана"

# Белый список обязан идти раньше бана, иначе «свои» попадут под автобан.
# nft печатает счётчики внутри правила, поэтому ищем строку по двум признакам.
chain="$(nft list chain inet "${TABLE}" input)"
allow_line="$(printf '%s\n' "${chain}" | grep -n '@allow4 accept' | head -1 | cut -d: -f1)"
ban_line="$(printf '%s\n' "${chain}" | grep -n '@banned4' | grep 'drop' | head -1 | cut -d: -f1)"
if [[ -z "${allow_line}" || -z "${ban_line}" ]]; then
  fail "в цепочке нет правил allow4/banned4"
fi
if (( allow_line >= ban_line )); then
  fail "белый список стоит после бана (allow ${allow_line}, ban ${ban_line})"
fi

# Автобан не должен уметь блокировать подсети.
if "${BIN_PATH}" guard ban "${TEST_NET}" >/dev/null 2>&1; then
  fail "подсеть ${TEST_NET} удалось забанить"
fi
log "подсеть забанить нельзя — ок"

# Свой адрес банить нельзя.
"${BIN_PATH}" guard allow add "${TEST_ADDR}" >/dev/null
if "${BIN_PATH}" guard ban "${TEST_ADDR}" >/dev/null 2>&1; then
  fail "адрес из белого списка удалось забанить"
fi
"${BIN_PATH}" guard allow remove "${TEST_ADDR}" >/dev/null
log "адрес из белого списка забанить нельзя — ок"

# Одиночный адрес банится, и у бана есть срок.
"${BIN_PATH}" guard ban "${TEST_ADDR}" --for 15m >/dev/null
element="$(nft list set inet "${TABLE}" banned4)"
printf '%s\n' "${element}" | grep -q "${TEST_ADDR}" || fail "адрес не попал в набор banned4"
printf '%s\n' "${element}" | grep -q "${TEST_ADDR} timeout" || fail "бан без срока"
log "бан одиночного адреса со сроком — ок"

"${BIN_PATH}" guard unban "${TEST_ADDR}" >/dev/null
if nft list set inet "${TABLE}" banned4 | grep -q "${TEST_ADDR}"; then
  fail "unban не убрал адрес"
fi
log "unban — ок"

"${BIN_PATH}" guard rollback >/dev/null
if nft list table inet "${TABLE}" >/dev/null 2>&1; then
  fail "rollback оставил таблицу ${TABLE}"
fi
if systemctl is-enabled rkn-guard-guard.service >/dev/null 2>&1; then
  fail "rollback оставил автозапуск щита"
fi
log "rollback чистый — ок"

log "все проверки щита пройдены"

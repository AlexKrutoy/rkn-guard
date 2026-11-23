package service

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func mustRender(t *testing.T, input GuardRenderInput) string {
	t.Helper()
	script, err := RenderGuardRules(input)
	if err != nil {
		t.Fatalf("RenderGuardRules: %v", err)
	}
	return script
}

func baseRenderInput(t *testing.T) GuardRenderInput {
	t.Helper()
	cfg := DefaultGuardConfig()
	allow4, allow6, err := GuardAllowPrefixes(cfg, nil)
	if err != nil {
		t.Fatalf("GuardAllowPrefixes: %v", err)
	}
	return GuardRenderInput{
		Config: cfg,
		Allow4: allow4,
		Allow6: allow6,
		Rate:   60,
		Ban:    time.Hour,
	}
}

func guardAllowAll(t *testing.T) []netip.Prefix {
	t.Helper()
	allow4, allow6, err := GuardAllowPrefixes(&GuardConfig{}, nil)
	if err != nil {
		t.Fatalf("GuardAllowPrefixes: %v", err)
	}
	return append(append([]netip.Prefix(nil), allow4...), allow6...)
}

// Белый список обязан стоять выше правил бана, иначе «свои» попадут под автобан.
func TestGuardRenderAllowBeforeBan(t *testing.T) {
	script := mustRender(t, baseRenderInput(t))
	allow := strings.Index(script, "@allow4 accept")
	ban := strings.Index(script, "@banned4 counter drop")
	if allow < 0 || ban < 0 {
		t.Fatalf("в скрипте нет правил allow4/ban:\n%s", script)
	}
	if allow > ban {
		t.Fatalf("белый список (%d) стоит после бана (%d)", allow, ban)
	}
}

// Подсеть автобаном не блокируется: правило добавляет только конкретный адрес.
func TestGuardRenderBanIsSingleAddress(t *testing.T) {
	script := mustRender(t, baseRenderInput(t))
	line := ""
	for _, candidate := range strings.Split(script, "\n") {
		if strings.Contains(candidate, "add @banned4") {
			line = candidate
			break
		}
	}
	if line == "" {
		t.Fatal("правило автобана не найдено")
	}
	if !strings.Contains(line, "ip saddr timeout") {
		t.Fatalf("автобан должен добавлять одиночный адрес: %s", line)
	}
	if strings.Contains(line, "@banned4 { ip saddr {") {
		t.Fatalf("в автобане появился набор адресов: %s", line)
	}
}

// У любого бана есть срок: адрес не может остаться в бане навсегда.
func TestGuardRenderBansAlwaysExpire(t *testing.T) {
	input := baseRenderInput(t)
	input.Bans = []GuardBan{
		{Addr: netip.MustParseAddr("203.0.113.7")},
		{Addr: netip.MustParseAddr("2001:db8::5"), Remaining: 90 * time.Second},
	}
	script := mustRender(t, input)
	for _, line := range strings.Split(script, "\n") {
		if !strings.Contains(line, "add element inet "+GuardTable+" banned") {
			continue
		}
		if !strings.Contains(line, "timeout ") {
			t.Fatalf("элемент бана без срока: %s", line)
		}
	}
	if !strings.Contains(script, "2001:db8::5 timeout") {
		t.Fatalf("бан IPv6 должен сохраниться со своим сроком:\n%s", script)
	}
}

// Своя таблица: скрипт не трогает чужие правила и цепочки.
func TestGuardRenderOnlyOwnTable(t *testing.T) {
	script := mustRender(t, baseRenderInput(t))
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "add ") && !strings.HasPrefix(trimmed, "delete ") {
			continue
		}
		if !strings.Contains(trimmed, " inet "+GuardTable) {
			t.Fatalf("строка выходит за пределы своей таблицы: %s", trimmed)
		}
	}
}

// Удаление старой таблицы — только когда она наша и существует.
func TestGuardRenderDeleteOnlyWhenExists(t *testing.T) {
	input := baseRenderInput(t)
	if script := mustRender(t, input); strings.Contains(script, "delete table") {
		t.Fatal("при отсутствии таблицы скрипт не должен её удалять")
	}
	input.Exists = true
	if script := mustRender(t, input); !strings.Contains(script, "delete table inet "+GuardTable) {
		t.Fatal("при существующей таблице нужна замена в одной транзакции")
	}
}

func TestGuardRenderRejectsBadRateAndBan(t *testing.T) {
	input := baseRenderInput(t)
	input.Rate = 0
	if _, err := RenderGuardRules(input); err == nil {
		t.Fatal("ожидалась ошибка: порог 0")
	}
	input = baseRenderInput(t)
	input.Ban = 10 * time.Second
	if _, err := RenderGuardRules(input); err == nil {
		t.Fatal("ожидалась ошибка: срок бана меньше минуты")
	}
}

// Пользователь может очистить порты: щит не должен притворяться, что работает.
func TestGuardRenderEmptyPortsIsRejected(t *testing.T) {
	input := baseRenderInput(t)
	input.Config.Ports = nil
	if _, err := RenderGuardRules(input); err == nil {
		t.Fatal("ожидалась ошибка: порты не заданы")
	}
}

func TestGuardRenderLoggingToggle(t *testing.T) {
	input := baseRenderInput(t)
	input.Config.Logging = false
	if script := mustRender(t, input); strings.Contains(script, "log prefix") {
		t.Fatal("журналирование выключено, а правила log остались")
	}
	input.Config.Logging = true
	if script := mustRender(t, input); !strings.Contains(script, "log prefix") {
		t.Fatal("журналирование включено, а правил log нет")
	}
}

func TestGuardRenderIPv6Toggle(t *testing.T) {
	input := baseRenderInput(t)
	input.Config.IPv6 = false
	input.Bans = []GuardBan{{Addr: netip.MustParseAddr("2001:db8::5"), Remaining: time.Minute}}
	script := mustRender(t, input)
	if strings.Contains(script, "banned6") || strings.Contains(script, "ip6 saddr") {
		t.Fatal("IPv6 выключен, а правила ip6 остались")
	}
}

func TestParseGuardDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"30m": 30 * time.Minute,
		"1h":  time.Hour,
		"6h":  6 * time.Hour,
	}
	for raw, want := range cases {
		got, err := ParseGuardDuration(raw)
		if err != nil {
			t.Fatalf("ParseGuardDuration(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("ParseGuardDuration(%q) = %v, ожидалось %v", raw, got, want)
		}
	}
	for _, raw := range []string{"", "час", "-5m", "0s"} {
		if _, err := ParseGuardDuration(raw); err == nil {
			t.Fatalf("ParseGuardDuration(%q) должен вернуть ошибку", raw)
		}
	}
}

func TestFormatGuardDurationRoundTrip(t *testing.T) {
	for _, want := range []time.Duration{30 * time.Minute, time.Hour, 6 * time.Hour} {
		formatted := FormatGuardDuration(want)
		got, err := ParseGuardDuration(formatted)
		if err != nil {
			t.Fatalf("ParseGuardDuration(%q): %v", formatted, err)
		}
		if got != want {
			t.Fatalf("%v -> %q -> %v", want, formatted, got)
		}
	}
}

func TestParseGuardPorts(t *testing.T) {
	ports, err := ParseGuardPorts([]string{"443", "8443,2053"})
	if err != nil {
		t.Fatalf("ParseGuardPorts: %v", err)
	}
	want := []int{443, 2053, 8443}
	if len(ports) != len(want) {
		t.Fatalf("получено %v, ожидалось %v", ports, want)
	}
	for index := range want {
		if ports[index] != want[index] {
			t.Fatalf("получено %v, ожидалось %v", ports, want)
		}
	}
	for _, raw := range []string{"0", "70000", "ssh", "-1", "443x"} {
		if _, err := ParseGuardPorts([]string{raw}); err == nil {
			t.Fatalf("ParseGuardPorts(%q) должен вернуть ошибку", raw)
		}
	}
}

// Бан подсети запрещён: одна ошибка в /16 отрезала бы весь дом провайдера.
func TestGuardBanTargetRefusesSubnet(t *testing.T) {
	allow := guardAllowAll(t)
	for _, raw := range []string{"203.0.113.0/24", "2001:db8::/32"} {
		if _, err := GuardBanTarget(raw, allow); err == nil {
			t.Fatalf("GuardBanTarget(%q) должен отказать", raw)
		}
	}
}

// Свой адрес банить нельзя: щит не должен резать того, кто его настраивает.
func TestGuardBanTargetRefusesAllowed(t *testing.T) {
	allow := guardAllowAll(t)
	for _, raw := range []string{"10.5.5.5", "192.168.1.10", "127.0.0.1", "::1", "100.64.3.3"} {
		if _, err := GuardBanTarget(raw, allow); err == nil {
			t.Fatalf("GuardBanTarget(%q) должен отказать: адрес в белом списке", raw)
		}
	}
}

func TestGuardBanTargetAcceptsPublicAddress(t *testing.T) {
	addr, err := GuardBanTarget("198.18.5.5", guardAllowAll(t))
	if err != nil {
		t.Fatalf("GuardBanTarget: %v", err)
	}
	if addr.String() != "198.18.5.5" {
		t.Fatalf("получен %s", addr)
	}
}

// Встроенный белый список обязан включать CGNAT: за ним мобильные операторы.
func TestGuardAllowIncludesCGNATAndLoopback(t *testing.T) {
	got := map[string]bool{}
	for _, prefix := range guardAllowAll(t) {
		got[prefix.String()] = true
	}
	want := []string{"100.64.0.0/10", "10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16", "169.254.0.0/16", "::1/128"}
	for _, prefix := range want {
		if !got[prefix] {
			t.Fatalf("в белом списке нет %s: %v", prefix, got)
		}
	}
}

// Встроенные подсети должны идти цельными блоками, а не рассыпаться на куски.
func TestGuardBuiltinAllowIsMinimal(t *testing.T) {
	got := map[string]bool{}
	for _, prefix := range guardAllowAll(t) {
		got[prefix.String()] = true
	}
	for _, bogus := range []string{"10.0.1.0/8", "100.64.0.0/22", "::/128", "127.0.0.1/8"} {
		if got[bogus] {
			t.Fatalf("битый префикс %s в белом списке: %v", bogus, got)
		}
	}
}

// Пользовательские записи не должны раздувать набор: пересечения склеиваются.
func TestGuardAllowPrefixesCollapse(t *testing.T) {
	cfg := &GuardConfig{Allow: []string{"203.0.113.0/24", "203.0.113.0/25", "198.51.100.7"}}
	allow4, _, err := GuardAllowPrefixes(cfg, nil)
	if err != nil {
		t.Fatalf("GuardAllowPrefixes: %v", err)
	}
	seen := map[string]bool{}
	for _, prefix := range allow4 {
		seen[prefix.String()] = true
	}
	if !seen["198.51.100.7/32"] {
		t.Fatalf("одиночный адрес не попал в белый список: %v", seen)
	}
	if seen["203.0.113.0/25"] {
		t.Fatalf("пересекающаяся запись не склеена: %v", seen)
	}
	if !seen["203.0.113.0/24"] {
		t.Fatalf("исходная подсеть потерялась: %v", seen)
	}
}

// Фид не имеет права отменить белый список.
func TestGuardRenderFeedCannotOverrideAllow(t *testing.T) {
	input := baseRenderInput(t)
	input.Feed4 = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	script := mustRender(t, input)
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "@feed4") && strings.Contains(line, "192.168") {
			t.Fatalf("подсеть из белого списка попала в фид: %s", line)
		}
	}
}

package service

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Адаптивный щит: count новых соединений в ядре и бан источника на время.
// Идея и правила взяты из HUBGuard (MIT), обвязка — из rkn-guard: конфиг, состояния,
// блокировка, откат и сборка живут в одном бинарнике.
const (
	GuardConfigPath = "/etc/rkn-guard/guard.json"
	GuardBansPath   = "/var/lib/rkn-guard/guard-bans.json"
	GuardFeedsPath  = "/var/lib/rkn-guard/guard-feeds.json"
	GuardUnitPath   = "/etc/systemd/system/rkn-guard-guard.service"

	// GuardTable — своя таблица. Чужие правила не трогаются, откат — удаление одной таблицы.
	GuardTable     = "rkn_guard_dynamic"
	GuardLogPrefix = "RKN-GUARD-BAN"

	GuardDefaultLevel = "enhanced"
	guardMaxAllow     = 500
	guardMaxFeeds     = 16
	guardMaxBans      = 20000
	guardMaxPorts     = 32
)

// GuardLevel — готовый профиль: сколько новых соединений в минуту с одного адреса
// считается флудом и на сколько адрес уходит в бан.
type GuardLevel struct {
	Rate int
	Ban  string
}

// GuardLevels — профили от мягкого к жёсткому. basic терпит мобильных клиентов за CGNAT,
// strict рассчитан на ноду без общего входного адреса.
var GuardLevels = map[string]GuardLevel{
	"relaxed":  {Rate: 900, Ban: "10m"},
	"basic":    {Rate: 600, Ban: "15m"},
	"enhanced": {Rate: 300, Ban: "1h"},
	"strict":   {Rate: 100, Ban: "6h"},
}

// GuardLevelNames — профили в порядке возрастания жёсткости (для меню и подсказок).
func GuardLevelNames() []string {
	return []string{"relaxed", "basic", "enhanced", "strict"}
}

// GuardFeed — внешний список сканерных адресов. Каждый адрес проверяется и не может
// отменить белый список: фид только добавляет цели, но свои адреса из него выбрасываются.
type GuardFeed struct {
	ID      int    `json:"id"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// GuardConfig — всё, что нужно для восстановления щита после перезагрузки.
type GuardConfig struct {
	Version    int         `json:"version"`
	Enabled    bool        `json:"enabled"`
	Level      string      `json:"level"`
	Rate       int         `json:"rate,omitempty"`     // только для level=custom
	BanTime    string      `json:"ban_time,omitempty"` // только для level=custom
	Ports      []int       `json:"ports"`
	Allow      []string    `json:"allow,omitempty"`
	Feeds      []GuardFeed `json:"feeds,omitempty"`
	NextFeedID int         `json:"next_feed_id,omitempty"`
	IPv6       bool        `json:"ipv6"`
	Logging    bool        `json:"logging"`
}

// DefaultGuardConfig — щит включён, 443, усиленный профиль, IPv6 и журнал включены.
// Дефолт совпадает с тем, что показывает меню: расхождения между формой и API нет.
func DefaultGuardConfig() *GuardConfig {
	return &GuardConfig{
		Version:    1,
		Enabled:    true,
		Level:      GuardDefaultLevel,
		Ports:      []int{443},
		IPv6:       true,
		Logging:    true,
		NextFeedID: 1,
	}
}

// LoadGuardConfig читает конфиг; отсутствие файла — это дефолт, а не ошибка.
func LoadGuardConfig(path string) (*GuardConfig, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return DefaultGuardConfig(), nil
	}
	if err != nil {
		return nil, err
	}
	cfg := DefaultGuardConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("повреждён файл настроек щита %s: %w", path, err)
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("неизвестная версия настроек щита: %d", cfg.Version)
	}
	return cfg, nil
}

// SaveGuardConfig пишет конфиг атомарно: недописанный файл не должен пережить сбой.
func SaveGuardConfig(path string, cfg *GuardConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0600)
}

// GuardRate возвращает порог и срок бана с учётом профиля.
func (c *GuardConfig) GuardRate() (int, time.Duration, error) {
	level := strings.ToLower(strings.TrimSpace(c.Level))
	if level == "" {
		level = GuardDefaultLevel
	}
	if level == "custom" {
		if c.Rate <= 0 {
			return 0, 0, fmt.Errorf("для профиля custom укажите --rate (новых соединений в минуту)")
		}
		ban, err := ParseGuardDuration(c.BanTime)
		if err != nil {
			return 0, 0, fmt.Errorf("--ban-time: %w", err)
		}
		return c.Rate, ban, nil
	}
	preset, ok := GuardLevels[level]
	if !ok {
		return 0, 0, fmt.Errorf("неизвестный профиль %q; доступны: %s или custom",
			c.Level, strings.Join(GuardLevelNames(), ", "))
	}
	ban, err := ParseGuardDuration(preset.Ban)
	if err != nil {
		return 0, 0, err
	}
	return preset.Rate, ban, nil
}

// Validate проверяет всё, что уйдёт в nft, до единой команды.
func (c *GuardConfig) Validate() error {
	if _, _, err := c.GuardRate(); err != nil {
		return err
	}
	if c.Rate < 0 || c.Rate > 1000000 {
		return fmt.Errorf("--rate: нужно число от 1 до 1000000")
	}
	ports, err := NormalizeGuardPorts(c.Ports)
	if err != nil {
		return err
	}
	c.Ports = ports
	if _, err := ParseGuardAllow(c.Allow); err != nil {
		return err
	}
	if len(c.Feeds) > guardMaxFeeds {
		return fmt.Errorf("можно добавить не более %d фидов", guardMaxFeeds)
	}
	seen := map[int]bool{}
	for _, feed := range c.Feeds {
		if feed.ID < 1 || seen[feed.ID] {
			return fmt.Errorf("некорректный номер фида %d", feed.ID)
		}
		seen[feed.ID] = true
		if _, err := NormalizeSourceURL(feed.URL); err != nil {
			return fmt.Errorf("фид %d: %w", feed.ID, err)
		}
	}
	if c.NextFeedID < 1 {
		c.NextFeedID = 1
	}
	return nil
}

// ParseGuardDuration принимает 45s, 30m, 6h, 2d или число секунд.
func ParseGuardDuration(value string) (time.Duration, error) {
	raw := strings.ToLower(strings.TrimSpace(value))
	if raw == "" {
		return 0, fmt.Errorf("укажите срок, например 30m, 1h или 6h")
	}
	if allDigits(raw) {
		seconds, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("некорректный срок %q", value)
		}
		return checkGuardDuration(time.Duration(seconds) * time.Second)
	}
	multiplier := time.Second
	switch raw[len(raw)-1] {
	case 's':
		multiplier = time.Second
	case 'm':
		multiplier = time.Minute
	case 'h':
		multiplier = time.Hour
	case 'd':
		multiplier = 24 * time.Hour
	default:
		return 0, fmt.Errorf("некорректный срок %q: используйте s, m, h или d", value)
	}
	number := raw[:len(raw)-1]
	if number == "" || len(number) > 6 || !allDigits(number) {
		return 0, fmt.Errorf("некорректный срок %q", value)
	}
	n, err := strconv.Atoi(number)
	if err != nil {
		return 0, fmt.Errorf("некорректный срок %q", value)
	}
	return checkGuardDuration(time.Duration(n) * multiplier)
}

func checkGuardDuration(d time.Duration) (time.Duration, error) {
	if d < time.Minute || d > 30*24*time.Hour {
		return 0, fmt.Errorf("срок должен быть от 1m до 30d")
	}
	return d, nil
}

// FormatGuardDuration печатает срок в форме, которую понимает nft.
func FormatGuardDuration(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	default:
		return fmt.Sprintf("%ds", int(d.Round(time.Second)/time.Second))
	}
}

// ParseGuardPorts разбирает «443, 8443;2053». Хоть одно неверное значение — отказ целиком:
// в nft уходят только проверенные числа.
func ParseGuardPorts(values []string) ([]int, error) {
	var items []string
	for _, chunk := range values {
		items = append(items, strings.FieldsFunc(chunk, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		})...)
	}
	ports := make([]int, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if len(item) > 5 || !allDigits(item) {
			return nil, fmt.Errorf("порт %q: нужно число от 1 до 65535", item)
		}
		n, err := strconv.Atoi(item)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("порт %q: нужно число от 1 до 65535", item)
		}
		ports = append(ports, n)
	}
	return NormalizeGuardPorts(ports)
}

// NormalizeGuardPorts убирает повторы и мусор, сохраняя порядок.
func NormalizeGuardPorts(ports []int) ([]int, error) {
	out := make([]int, 0, len(ports))
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("порт %d: нужно число от 1 до 65535", port)
		}
		if seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("не выбран ни один порт: щиту нечего защищать")
	}
	if len(out) > guardMaxPorts {
		return nil, fmt.Errorf("не более %d портов", guardMaxPorts)
	}
	sort.Ints(out)
	return out, nil
}

// ParseGuardAllow принимает адреса и подсети. 0.0.0.0/0 и ::/0 запрещены: «разрешить всё»
// превращает щит в выключенный щит, и это должно быть явным решением, а не опечаткой.
func ParseGuardAllow(values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		for _, item := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
		}) {
			prefix, err := parseGuardPrefix(item)
			if err != nil {
				return nil, err
			}
			out = append(out, prefix)
		}
	}
	if len(out) > guardMaxAllow {
		return nil, fmt.Errorf("в белом списке не более %d записей", guardMaxAllow)
	}
	return CollapseGuardPrefixes(out), nil
}

func parseGuardPrefix(item string) (netip.Prefix, error) {
	if strings.Contains(item, "/") {
		prefix, err := netip.ParsePrefix(item)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%q — не адрес и не подсеть (пример: 1.2.3.4 или 10.0.0.0/8)", item)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return netip.Prefix{}, fmt.Errorf("%s разрешает вообще всё; щит так не работает", item)
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(item)
	if err != nil || addr.Zone() != "" || addr.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q — не адрес и не подсеть (пример: 1.2.3.4 или 10.0.0.0/8)", item)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// GuardBuiltinAllow — то, что не банится никогда: loopback, приватные сети и CGNAT.
// За 100.64.0.0/10 сидят мобильные операторы: один такой бан отрезал бы много клиентов сразу.
func GuardBuiltinAllow() []netip.Prefix {
	must := func(value string) netip.Prefix { return netip.MustParsePrefix(value) }
	return []netip.Prefix{
		must("127.0.0.0/8"), must("10.0.0.0/8"), must("172.16.0.0/12"),
		must("192.168.0.0/16"), must("100.64.0.0/10"), must("169.254.0.0/16"),
		must("::1/128"), must("fc00::/7"), must("fe80::/10"),
	}
}

// GuardAllowPrefixes собирает белый список: встроенные сети + записи человека + адрес
// текущей SSH-сессии. Возвращает IPv4 и IPv6 отдельно, схлопнутые и без пересечений —
// nft-набор объявлен interval и на пересечениях отвергает весь ruleset.
func GuardAllowPrefixes(cfg *GuardConfig, extra []netip.Prefix) (v4, v6 []netip.Prefix, err error) {
	all := GuardBuiltinAllow()
	if cfg != nil {
		configured, err := ParseGuardAllow(cfg.Allow)
		if err != nil {
			return nil, nil, err
		}
		all = append(all, configured...)
	}
	all = append(all, extra...)
	for _, prefix := range CollapseGuardPrefixes(all) {
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}
	return v4, v6, nil
}

// CollapseGuardPrefixes схлопывает подсети до минимального набора: 10.0.0.0/24 + 10.0.1.0/24
// дают 10.0.0.0/23, вложенные записи выбрасываются. Работает через интервалы, поэтому
// результат точный и не зависит от порядка входа.
func CollapseGuardPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	type interval struct {
		start, end *big.Int
		is4        bool
	}
	var intervals []interval
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		start, end, is4 := guardPrefixRange(prefix)
		intervals = append(intervals, interval{start, end, is4})
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].is4 != intervals[j].is4 {
			return intervals[i].is4
		}
		if c := intervals[i].start.Cmp(intervals[j].start); c != 0 {
			return c < 0
		}
		return intervals[i].end.Cmp(intervals[j].end) < 0
	})
	var merged []interval
	for _, current := range intervals {
		if n := len(merged); n > 0 && merged[n-1].is4 == current.is4 {
			last := &merged[n-1]
			next := new(big.Int).Add(last.end, big.NewInt(1))
			if current.start.Cmp(next) <= 0 {
				if current.end.Cmp(last.end) > 0 {
					last.end = current.end
				}
				continue
			}
		}
		merged = append(merged, current)
	}
	out := make([]netip.Prefix, 0, len(merged))
	for _, item := range merged {
		out = append(out, guardRangePrefixes(item.start, item.end, item.is4)...)
	}
	return out
}

func guardPrefixRange(prefix netip.Prefix) (start, end *big.Int, is4 bool) {
	addr := prefix.Masked().Addr()
	if addr.Is4() {
		bytes := addr.As4()
		value := new(big.Int).SetBytes(bytes[:])
		size := new(big.Int).Lsh(big.NewInt(1), uint(32-prefix.Bits()))
		return value, new(big.Int).Sub(new(big.Int).Add(value, size), big.NewInt(1)), true
	}
	bytes := addr.As16()
	value := new(big.Int).SetBytes(bytes[:])
	size := new(big.Int).Lsh(big.NewInt(1), uint(128-prefix.Bits()))
	return value, new(big.Int).Sub(new(big.Int).Add(value, size), big.NewInt(1)), false
}

// guardRangePrefixes превращает непрерывный интервал в минимальный набор CIDR:
// блок максимального размера, выровненный по текущему адресу и не выходящий за конец.
func guardRangePrefixes(start, end *big.Int, is4 bool) []netip.Prefix {
	bits := 128
	if is4 {
		bits = 32
	}
	full := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	one := big.NewInt(1)
	var out []netip.Prefix
	current := new(big.Int).Set(start)
	for current.Cmp(end) <= 0 {
		// Максимальный блок, начинающийся ровно здесь: младший установленный бит адреса.
		size := new(big.Int).And(current, new(big.Int).Neg(current))
		if size.Sign() == 0 {
			size.Set(full)
		}
		remaining := new(big.Int).Add(new(big.Int).Sub(end, current), one)
		for size.Cmp(remaining) > 0 {
			size.Rsh(size, 1)
		}
		length := 0
		for probe := new(big.Int).Set(size); probe.Cmp(one) > 0; probe.Rsh(probe, 1) {
			length++
		}
		bytes := make([]byte, bits/8)
		current.FillBytes(bytes)
		addr, ok := netip.AddrFromSlice(bytes)
		if !ok {
			break
		}
		out = append(out, netip.PrefixFrom(addr, bits-length))
		current = new(big.Int).Add(current, size)
	}
	return out
}

// GuardAddrInPrefixes — точечная проверка: попадает ли адрес в любой из префиксов.
func GuardAddrInPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// GuardBanTarget проверяет цель ручного бана: один адрес, не подсеть, не из белого списка.
// Подсеть автобаном не блокируется никогда — это и есть главный урок HUBGuard.
func GuardBanTarget(raw string, allow []netip.Prefix) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, fmt.Errorf("укажите один IPv4 или IPv6 адрес")
	}
	if strings.Contains(raw, "/") {
		return netip.Addr{}, fmt.Errorf("%s — подсеть; бан возможен только по одному адресу", raw)
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" || addr.Is4In6() {
		return netip.Addr{}, fmt.Errorf("%q — не IPv4 и не IPv6 адрес", raw)
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("%s — служебный адрес, банить его бессмысленно", addr)
	}
	if GuardAddrInPrefixes(addr, allow) {
		return netip.Addr{}, fmt.Errorf("%s в белом списке: бан отменил бы правило «своих не режем»", addr)
	}
	return addr.Unmap(), nil
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

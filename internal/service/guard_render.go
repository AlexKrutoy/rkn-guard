package service

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const guardElementsPerLine = 200

// GuardRenderInput — всё, из чего собирается ruleset. Ничего не читает с диска:
// благодаря этому plan и apply показывают ровно одно и то же.
type GuardRenderInput struct {
	Config *GuardConfig
	Allow4 []netip.Prefix
	Allow6 []netip.Prefix
	Feed4  []netip.Prefix
	Feed6  []netip.Prefix
	Bans   []GuardBan
	Exists bool
	Rate   int
	Ban    time.Duration
}

// RenderGuardRules собирает скрипт для nft. Порядок правил — это и есть политика:
// свои адреса проверяются первыми, поэтому бан не может отрезать белый список.
func RenderGuardRules(in GuardRenderInput) (string, error) {
	if in.Config == nil {
		return "", fmt.Errorf("нет настроек щита")
	}
	if in.Rate < 1 || in.Rate > 1000000 {
		return "", fmt.Errorf("порог должен быть от 1 до 1000000 новых соединений в минуту")
	}
	if in.Ban < time.Minute || in.Ban > 30*24*time.Hour {
		return "", fmt.Errorf("срок бана должен быть от 1m до 30d")
	}
	ports, err := NormalizeGuardPorts(in.Config.Ports)
	if err != nil {
		return "", err
	}
	allow4, err := guardFamilyPrefixes(in.Allow4, true)
	if err != nil {
		return "", fmt.Errorf("белый список IPv4: %w", err)
	}
	allow6, err := guardFamilyPrefixes(in.Allow6, false)
	if err != nil {
		return "", fmt.Errorf("белый список IPv6: %w", err)
	}
	feed4, err := guardFamilyPrefixes(in.Feed4, true)
	if err != nil {
		return "", fmt.Errorf("фиды IPv4: %w", err)
	}
	feed6, err := guardFamilyPrefixes(in.Feed6, false)
	if err != nil {
		return "", fmt.Errorf("фиды IPv6: %w", err)
	}
	// Фид не может отменить белый список: пересечения вырезаем ещё до nft.
	feed4 = guardDropCovered(feed4, allow4)
	feed6 = guardDropCovered(feed6, allow6)

	withIPv6 := in.Config.IPv6
	ban := FormatGuardDuration(in.Ban)
	rate := fmt.Sprintf("%d/minute", in.Rate)
	burst := fmt.Sprintf("burst %d packets", in.Rate)
	portList := guardPortList(ports)
	logging := in.Config.Logging

	var out strings.Builder
	out.WriteString("# rkn-guard: адаптивный щит (nftables). Файл собран программой, руками не правится.\n")
	if in.Exists {
		// Одна транзакция: старые правила заменяются новыми целиком, без окна без защиты.
		fmt.Fprintf(&out, "delete table inet %s\n", GuardTable)
	}
	fmt.Fprintf(&out, "add table inet %s\n", GuardTable)
	fmt.Fprintf(&out, "add set inet %s allow4 { type ipv4_addr; flags interval; }\n", GuardTable)
	fmt.Fprintf(&out, "add set inet %s banned4 { type ipv4_addr; flags timeout; timeout %s; size 65536; }\n", GuardTable, ban)
	fmt.Fprintf(&out, "add set inet %s feed4 { type ipv4_addr; flags interval; size 65536; }\n", GuardTable)
	fmt.Fprintf(&out, "add set inet %s flood4 { type ipv4_addr; flags dynamic,timeout; timeout %s; size 65535; }\n",
		GuardTable, FormatGuardDuration(2*time.Minute))
	if withIPv6 {
		fmt.Fprintf(&out, "add set inet %s allow6 { type ipv6_addr; flags interval; }\n", GuardTable)
		fmt.Fprintf(&out, "add set inet %s banned6 { type ipv6_addr; flags timeout; timeout %s; size 65536; }\n", GuardTable, ban)
		fmt.Fprintf(&out, "add set inet %s feed6 { type ipv6_addr; flags interval; size 65536; }\n", GuardTable)
		fmt.Fprintf(&out, "add set inet %s flood6 { type ipv6_addr; flags dynamic,timeout; timeout %s; size 65535; }\n",
			GuardTable, FormatGuardDuration(2*time.Minute))
	}
	// priority -9: после rkn_guard (-10), но до filter/ufw (0). Чужие таблицы не трогаются.
	fmt.Fprintf(&out, "add chain inet %s input { type filter hook input priority -9; policy accept; }\n", GuardTable)
	fmt.Fprintf(&out, "add rule inet %s input ct state established,related accept\n", GuardTable)
	fmt.Fprintf(&out, "add rule inet %s input iif \"lo\" accept\n", GuardTable)
	fmt.Fprintf(&out, "add rule inet %s input ip saddr @allow4 accept\n", GuardTable)
	if withIPv6 {
		fmt.Fprintf(&out, "add rule inet %s input ip6 saddr @allow6 accept\n", GuardTable)
	}
	if logging {
		fmt.Fprintf(&out, "add rule inet %s input ip saddr @feed4 limit rate 12/minute burst 6 packets log prefix \"%s-v4: \" level warn\n",
			GuardTable, GuardLogPrefix)
	} else {
		_ = logging
	}
	fmt.Fprintf(&out, "add rule inet %s input ip saddr @feed4 counter drop\n", GuardTable)
	if withIPv6 {
		if logging {
			fmt.Fprintf(&out, "add rule inet %s input ip6 saddr @feed6 limit rate 12/minute burst 6 packets log prefix \"%s-v6: \" level warn\n",
				GuardTable, GuardLogPrefix)
		}
		fmt.Fprintf(&out, "add rule inet %s input ip6 saddr @feed6 counter drop\n", GuardTable)
	}
	if logging {
		fmt.Fprintf(&out, "add rule inet %s input ip saddr @banned4 limit rate 12/minute burst 6 packets log prefix \"%s-v4: \" level warn\n",
			GuardTable, GuardLogPrefix)
	}
	fmt.Fprintf(&out, "add rule inet %s input ip saddr @banned4 counter drop\n", GuardTable)
	if withIPv6 {
		if logging {
			fmt.Fprintf(&out, "add rule inet %s input ip6 saddr @banned6 limit rate 12/minute burst 6 packets log prefix \"%s-v6: \" level warn\n",
				GuardTable, GuardLogPrefix)
		}
		fmt.Fprintf(&out, "add rule inet %s input ip6 saddr @banned6 counter drop\n", GuardTable)
	}
	fmt.Fprintf(&out, "add rule inet %s input tcp dport { %s } ct state new update @flood4 { ip saddr limit rate over %s %s } add @banned4 { ip saddr timeout %s } counter drop\n",
		GuardTable, portList, rate, burst, ban)
	if withIPv6 {
		fmt.Fprintf(&out, "add rule inet %s input tcp dport { %s } ct state new update @flood6 { ip6 saddr limit rate over %s %s } add @banned6 { ip6 saddr timeout %s } counter drop\n",
			GuardTable, portList, rate, burst, ban)
	}

	guardWriteElements(&out, "allow4", guardPrefixStrings(allow4))
	guardWriteElements(&out, "banned4", guardBanElements(in.Bans, true, in.Ban))
	guardWriteElements(&out, "feed4", guardPrefixStrings(feed4))
	if withIPv6 {
		guardWriteElements(&out, "allow6", guardPrefixStrings(allow6))
		guardWriteElements(&out, "banned6", guardBanElements(in.Bans, false, in.Ban))
		guardWriteElements(&out, "feed6", guardPrefixStrings(feed6))
	}
	return out.String(), nil
}

// guardWriteElements печатает элементы набора кусками: одна строка на тысячи адресов
// превращается в мегабайт текста и медленный разбор.
func guardWriteElements(out *strings.Builder, set string, values []string) {
	for start := 0; start < len(values); start += guardElementsPerLine {
		end := start + guardElementsPerLine
		if end > len(values) {
			end = len(values)
		}
		fmt.Fprintf(out, "add element inet %s %s { %s }\n", GuardTable, set, strings.Join(values[start:end], ", "))
	}
}

// guardBanElements превращает сохранённые баны в элементы с остатком срока.
func guardBanElements(bans []GuardBan, ipv4 bool, max time.Duration) []string {
	out := make([]string, 0, len(bans))
	for _, ban := range bans {
		if !ban.Addr.IsValid() || ban.Addr.Is4() != ipv4 {
			continue
		}
		remaining := ban.Remaining
		if remaining <= 0 {
			continue
		}
		if remaining > max {
			remaining = max
		}
		out = append(out, fmt.Sprintf("%s timeout %s", ban.Addr, FormatGuardDuration(remaining)))
		if len(out) >= guardMaxBans {
			break
		}
	}
	sort.Strings(out)
	return out
}

func guardFamilyPrefixes(prefixes []netip.Prefix, ipv4 bool) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("некорректная подсеть в списке")
		}
		if prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, fmt.Errorf("%s: недопустимая запись", prefix)
		}
		if prefix.Addr().Is4() != ipv4 {
			return nil, fmt.Errorf("%s: не то семейство адресов", prefix)
		}
		out = append(out, prefix.Masked())
	}
	return CollapseGuardPrefixes(out), nil
}

// guardDropCovered убирает из списка всё, что попадает в белый список.
func guardDropCovered(prefixes, allow []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		covered := false
		for _, allowed := range allow {
			if allowed.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, prefix)
		}
	}
	return out
}

func guardPortList(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("%d", port))
	}
	return strings.Join(parts, ", ")
}

// GuardPlan печатает то, что будет применено, не меняя систему.
func GuardPlan(in GuardRenderInput) (string, error) {
	return RenderGuardRules(in)
}

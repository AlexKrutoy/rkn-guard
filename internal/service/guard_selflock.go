package service

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// GuardPeerIP — адрес, с которого пришла текущая сессия. Если это SSH, адрес берётся
// из окружения, которое выставляет sshd: другого надёжного источника без root-хуков нет.
func GuardPeerIP() (netip.Addr, error) {
	for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT"} {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		addr, err := netip.ParseAddr(strings.Trim(fields[0], "[]"))
		if err != nil || addr.Zone() != "" || addr.Is4In6() {
			continue
		}
		return addr.Unmap(), nil
	}
	return netip.Addr{}, fmt.Errorf("сессия не по SSH: адрес клиента неизвестен")
}

// GuardSelfLockoutRisk отвечает на вопрос «отрежут ли эти правила меня самого».
// Возвращает текст причины, если адрес сессии попадает под блокировку и не прикрыт
// белым списком. Это ровно тот случай, из-за которого люди теряют сервер.
func GuardSelfLockoutRisk(peer netip.Addr, allow, blocked []netip.Prefix) string {
	if !peer.IsValid() {
		return ""
	}
	if GuardAddrInPrefixes(peer, allow) {
		return ""
	}
	if !GuardAddrInPrefixes(peer, blocked) {
		return ""
	}
	for _, prefix := range blocked {
		if prefix.Contains(peer) {
			return fmt.Sprintf("адрес текущей сессии %s попадает в блокируемую подсеть %s", peer, prefix)
		}
	}
	return fmt.Sprintf("адрес текущей сессии %s попадает в блокируемую подсеть", peer)
}

// kernelBlockedPrefixes читает подсети, которые уже режет rkn_guard (nft-режим).
func kernelBlockedPrefixes(cmd *CommandService) []netip.Prefix {
	var out []netip.Prefix
	for _, set := range []string{"blocked4", "blocked6"} {
		output, err := cmd.RunOutputQuiet("nft", "-j", "list", "set", "inet", "rkn_guard", set)
		if err != nil {
			continue
		}
		out = append(out, parseNFTPrefixSet(output)...)
	}
	return out
}

// parseNFTPrefixSet разбирает элементы interval-набора: строки «1.2.3.0/24» или объекты с val.
func parseNFTPrefixSet(output string) []netip.Prefix {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(output), &doc); err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			value := ""
			var plain string
			if err := json.Unmarshal(raw, &plain); err == nil {
				value = plain
			} else {
				var object struct {
					Val string `json:"val"`
				}
				if err := json.Unmarshal(raw, &object); err != nil {
					continue
				}
				value = object.Val
			}
			prefix, err := parseGuardPrefix(value)
			if err != nil {
				continue
			}
			out = append(out, prefix)
		}
	}
	return out
}

// ipsetBlockedPrefixes читает те же подсети в режиме iptables: ipset save отдаёт
// по одной записи «add NAME 1.2.3.0/24».
func ipsetBlockedPrefixes(cmd *CommandService) []netip.Prefix {
	var out []netip.Prefix
	for _, set := range []string{ipsetV4Name, ipsetV6Name} {
		output, err := cmd.RunOutputQuiet("ipset", "save", set)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != "add" {
				continue
			}
			prefix, err := parseGuardPrefix(fields[2])
			if err != nil {
				continue
			}
			out = append(out, prefix)
		}
	}
	return out
}

// GuardBlockedPrefixes собирает то, что уже заблокировано, любым из двух режимов.
func GuardBlockedPrefixes(cmd *CommandService, backend string) []netip.Prefix {
	if backend == "iptables" {
		return ipsetBlockedPrefixes(cmd)
	}
	return kernelBlockedPrefixes(cmd)
}

// GuardAllowForBlocklist — белый список для основной таблицы блокировки: встроенные
// сети, записи из настроек щита и адрес текущей сессии. Читается best-effort.
func GuardAllowForBlocklist() ([]netip.Prefix, error) {
	cfg, err := LoadGuardConfig(GuardConfigPath)
	if err != nil {
		return nil, err
	}
	var extra []netip.Prefix
	if peer, peerErr := GuardPeerIP(); peerErr == nil {
		extra = append(extra, netip.PrefixFrom(peer, peer.BitLen()))
	}
	v4, v6, err := GuardAllowPrefixes(cfg, extra)
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}

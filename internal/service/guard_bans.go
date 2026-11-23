package service

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GuardBan — активный бан. В ядре он живёт с таймаутом, а на диске — с временем
// истечения: после перезагрузки щит восстанавливает то, что ещё не рассосалось само.
type GuardBan struct {
	Addr      netip.Addr
	Remaining time.Duration
}

type guardBanFile struct {
	Version int               `json:"version"`
	Bans    map[string]string `json:"bans"` // адрес -> RFC3339 момент истечения
}

// LoadGuardBans читает сохранённые баны, молча выбрасывая истёкшие и некорректные.
func LoadGuardBans(path string) ([]GuardBan, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var file guardBanFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("повреждён файл банов %s: %w", path, err)
	}
	now := time.Now()
	var out []GuardBan
	for raw, expires := range file.Bans {
		addr, err := netip.ParseAddr(raw)
		if err != nil || addr.Is4In6() {
			continue
		}
		moment, err := time.Parse(time.RFC3339, expires)
		if err != nil || !moment.After(now) {
			continue
		}
		out = append(out, GuardBan{Addr: addr.Unmap(), Remaining: moment.Sub(now)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	if len(out) > guardMaxBans {
		out = out[:guardMaxBans]
	}
	return out, nil
}

// SaveGuardBans пишет баны атомарно; пустой список — это тоже состояние.
func SaveGuardBans(path string, bans []GuardBan) error {
	file := guardBanFile{Version: 1, Bans: map[string]string{}}
	now := time.Now()
	for _, ban := range bans {
		if ban.Remaining <= 0 || !ban.Addr.IsValid() {
			continue
		}
		file.Bans[ban.Addr.String()] = now.Add(ban.Remaining).UTC().Format(time.RFC3339)
		if len(file.Bans) >= guardMaxBans {
			break
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0600)
}

// MergeGuardBans объединяет сохранённые баны с новыми, оставляя более поздний срок.
func MergeGuardBans(existing []GuardBan, extra []GuardBan) []GuardBan {
	byAddr := map[netip.Addr]time.Duration{}
	order := make([]netip.Addr, 0, len(existing)+len(extra))
	for _, ban := range append(append([]GuardBan(nil), existing...), extra...) {
		if !ban.Addr.IsValid() || ban.Remaining <= 0 {
			continue
		}
		addr := ban.Addr.Unmap()
		current, seen := byAddr[addr]
		if !seen {
			order = append(order, addr)
		}
		if ban.Remaining > current {
			byAddr[addr] = ban.Remaining
		}
	}
	out := make([]GuardBan, 0, len(order))
	for _, addr := range order {
		out = append(out, GuardBan{Addr: addr, Remaining: byAddr[addr]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out
}

// DropGuardBan убирает адрес из списка.
func DropGuardBan(bans []GuardBan, addr netip.Addr) ([]GuardBan, bool) {
	out := make([]GuardBan, 0, len(bans))
	removed := false
	for _, ban := range bans {
		if ban.Addr.Unmap() == addr.Unmap() {
			removed = true
			continue
		}
		out = append(out, ban)
	}
	return out, removed
}

// kernelGuardBans читает активные баны из ядра. nft отдаёт элементы JSON, где «elem»
// бывает и строкой, и объектом с val/expires — разбираем оба вида.
func kernelGuardBans(cmd *CommandService, set string) ([]GuardBan, error) {
	output, err := cmd.RunOutput("nft", "-j", "list", "set", "inet", GuardTable, set)
	if err != nil {
		if strings.Contains(err.Error(), "No such file") || strings.Contains(output, "No such") {
			return nil, nil
		}
		return nil, err
	}
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(output), &doc); err != nil {
		return nil, fmt.Errorf("не разобрать ответ nft: %w", err)
	}
	var out []GuardBan
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			// nft отдаёт элемент либо строкой, либо объектом {"elem":{...}},
			// либо плоско {"val":...} в старых сборках. Разбираем все три вида.
			var plain string
			if err := json.Unmarshal(raw, &plain); err == nil {
				if addr, err := netip.ParseAddr(plain); err == nil {
					out = append(out, GuardBan{Addr: addr.Unmap()})
				}
				continue
			}
			var wrapper struct {
				Elem *json.RawMessage `json:"elem"`
			}
			if err := json.Unmarshal(raw, &wrapper); err == nil && wrapper.Elem != nil {
				raw = *wrapper.Elem
				if err := json.Unmarshal(raw, &plain); err == nil {
					if addr, err := netip.ParseAddr(plain); err == nil {
						out = append(out, GuardBan{Addr: addr.Unmap()})
					}
					continue
				}
			}
			var object struct {
				Val     string  `json:"val"`
				Expires float64 `json:"expires"`
			}
			if err := json.Unmarshal(raw, &object); err != nil {
				continue
			}
			addr, err := netip.ParseAddr(object.Val)
			if err != nil {
				continue
			}
			out = append(out, GuardBan{
				Addr:      addr.Unmap(),
				Remaining: time.Duration(object.Expires * float64(time.Second)),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out, nil
}

// kernelGuardCounter суммирует пакеты и байты правил drop в нашей цепочке.
func kernelGuardCounter(cmd *CommandService) (packets, bytes uint64, err error) {
	output, err := cmd.RunOutputQuiet("nft", "-j", "list", "chain", "inet", GuardTable, "input")
	if err != nil {
		return 0, 0, nil
	}
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Expr []struct {
					Counter *struct {
						Packets uint64 `json:"packets"`
						Bytes   uint64 `json:"bytes"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(output), &doc); err != nil {
		return 0, 0, fmt.Errorf("не разобрать счётчики nft: %w", err)
	}
	for _, item := range doc.Nftables {
		if item.Rule == nil {
			continue
		}
		for _, expr := range item.Rule.Expr {
			if expr.Counter != nil {
				packets += expr.Counter.Packets
				bytes += expr.Counter.Bytes
			}
		}
	}
	return packets, bytes, nil
}

// guardTableExists проверяет нашу таблицу, не трогая остальные правила.
func guardTableExists(cmd *CommandService) bool {
	return nftTableExists(cmd, GuardTable)
}

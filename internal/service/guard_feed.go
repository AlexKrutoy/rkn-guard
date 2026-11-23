package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	guardFeedMaxBytes  = 16 << 20
	guardFeedMaxItems  = 100000
	guardFeedMaxTotal  = 200000
	guardFeedFreshness = 24 * time.Hour
	// Шире этих границ фид не принимается: «0.0.0.0/0» из чужого списка выключил бы ноду.
	guardFeedMinBits4 = 16
	guardFeedMinBits6 = 32
)

type guardFeedEntry struct {
	UpdatedAt string   `json:"updated_at"`
	Prefixes  []string `json:"prefixes"`
	LastError string   `json:"last_error,omitempty"`
}

type guardFeedCache struct {
	Version int                       `json:"version"`
	Entries map[string]guardFeedEntry `json:"entries"`
}

// GuardFeedState — результат синхронизации: готовые префиксы и предупреждения,
// которые нужно показать человеку, а не проглотить.
type GuardFeedState struct {
	Prefixes []netip.Prefix
	Warnings []string
	Updated  int
	Used     int
}

func loadGuardFeedCache(path string) (*guardFeedCache, error) {
	cache := &guardFeedCache{Version: 1, Entries: map[string]guardFeedEntry{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cache, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cache); err != nil {
		// Битый кеш не должен мешать щиту: начинаем с пустого и перекачаем.
		return &guardFeedCache{Version: 1, Entries: map[string]guardFeedEntry{}}, nil
	}
	if cache.Entries == nil {
		cache.Entries = map[string]guardFeedEntry{}
	}
	return cache, nil
}

func saveGuardFeedCache(path string, cache *guardFeedCache) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0600)
}

// fetchGuardFeed скачивает список: только HTTP(S), только разумный размер.
func fetchGuardFeed(url string, client *http.Client) (string, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "rkn-guard/adaptive-guard")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, guardFeedMaxBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > guardFeedMaxBytes {
		return "", fmt.Errorf("список больше %d МБ", guardFeedMaxBytes>>20)
	}
	return string(body), nil
}

// ParseGuardFeed разбирает текст фида. Строки с # и // — комментарии; принимаются
// адреса и подсети; всё, что шире /16 (v4) или /32 (v6), отбрасывается.
// Возвращает префиксы, число отброшенных «своих» адресов и ошибку разбора.
func ParseGuardFeed(text string, allow []netip.Prefix) (prefixes []netip.Prefix, skippedAllow int, err error) {
	seen := map[netip.Prefix]bool{}
	scanned := 0
	for _, rawLine := range strings.Split(text, "\n") {
		line := rawLine
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		for _, field := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r'
		}) {
			if field == "" {
				continue
			}
			scanned++
			if scanned > guardFeedMaxItems*4 {
				return nil, skippedAllow, fmt.Errorf("фид слишком большой: больше %d записей", guardFeedMaxItems*4)
			}
			prefix, parseErr := parseGuardPrefix(field)
			if parseErr != nil {
				continue
			}
			if prefix.Addr().Is4() && prefix.Bits() < guardFeedMinBits4 {
				continue
			}
			if prefix.Addr().Is6() && prefix.Bits() < guardFeedMinBits6 {
				continue
			}
			if GuardAddrInPrefixes(prefix.Addr(), allow) {
				skippedAllow++
				continue
			}
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
			if len(prefixes) > guardFeedMaxItems {
				return nil, skippedAllow, fmt.Errorf("фид содержит больше %d подсетей", guardFeedMaxItems)
			}
		}
	}
	return prefixes, skippedAllow, nil
}

// SyncGuardFeeds обновляет включённые фиды. Сбой загрузки не роняет щит: берётся
// последняя проверенная копия, а человек получает предупреждение.
func SyncGuardFeeds(cfg *GuardConfig, allow []netip.Prefix, cachePath string, client *http.Client) (*GuardFeedState, error) {
	state := &GuardFeedState{}
	cache, err := loadGuardFeedCache(cachePath)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var combined []netip.Prefix
	changed := false
	for _, feed := range cfg.Feeds {
		if !feed.Enabled {
			continue
		}
		state.Used++
		entry := cache.Entries[feed.URL]
		fresh := false
		if entry.UpdatedAt != "" {
			if moment, err := time.Parse(time.RFC3339, entry.UpdatedAt); err == nil {
				fresh = time.Since(moment) < guardFeedFreshness
			}
		}
		if !fresh {
			text, fetchErr := fetchGuardFeed(feed.URL, client)
			if fetchErr != nil {
				entry.LastError = fetchErr.Error()
				if len(entry.Prefixes) > 0 {
					state.Warnings = append(state.Warnings, fmt.Sprintf(
						"%s: %v. Используется последняя проверенная копия от %s", feed.URL, fetchErr, entry.UpdatedAt))
				} else {
					state.Warnings = append(state.Warnings, fmt.Sprintf("%s: %v. Фид пропущен", feed.URL, fetchErr))
					cache.Entries[feed.URL] = entry
					changed = true
					continue
				}
			} else {
				parsed, skipped, parseErr := ParseGuardFeed(text, allow)
				if parseErr != nil {
					entry.LastError = parseErr.Error()
					if len(entry.Prefixes) == 0 {
						state.Warnings = append(state.Warnings, fmt.Sprintf("%s: %v. Фид пропущен", feed.URL, parseErr))
						cache.Entries[feed.URL] = entry
						changed = true
						continue
					}
					state.Warnings = append(state.Warnings, fmt.Sprintf(
						"%s: %v. Используется прежняя копия от %s", feed.URL, parseErr, entry.UpdatedAt))
				} else {
					if skipped > 0 {
						state.Warnings = append(state.Warnings, fmt.Sprintf(
							"%s: %d записей из белого списка отброшено", feed.URL, skipped))
					}
					entry = guardFeedEntry{
						UpdatedAt: time.Now().UTC().Format(time.RFC3339),
						Prefixes:  guardPrefixStrings(parsed),
					}
					state.Updated++
				}
			}
			cache.Entries[feed.URL] = entry
			changed = true
		}
		stored := make([]netip.Prefix, 0, len(entry.Prefixes))
		for _, raw := range entry.Prefixes {
			prefix, parseErr := parseGuardPrefix(raw)
			if parseErr != nil {
				continue
			}
			if GuardAddrInPrefixes(prefix.Addr(), allow) {
				continue
			}
			stored = append(stored, prefix)
		}
		combined = append(combined, stored...)
	}
	// Чистим кеш от фидов, которые больше не настроены.
	configured := map[string]bool{}
	for _, feed := range cfg.Feeds {
		configured[feed.URL] = true
	}
	for url := range cache.Entries {
		if !configured[url] {
			delete(cache.Entries, url)
			changed = true
		}
	}
	if changed {
		if err := saveGuardFeedCache(cachePath, cache); err != nil {
			state.Warnings = append(state.Warnings, fmt.Sprintf("кеш фидов не сохранён: %v", err))
		}
	}
	state.Prefixes = CollapseGuardPrefixes(combined)
	if len(state.Prefixes) > guardFeedMaxTotal {
		state.Prefixes = state.Prefixes[:guardFeedMaxTotal]
		state.Warnings = append(state.Warnings, fmt.Sprintf("фиды обрезаны до %d подсетей", guardFeedMaxTotal))
	}
	return state, nil
}

func guardPrefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	sort.Strings(out)
	return out
}

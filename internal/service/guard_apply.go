package service

import (
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

const guardAllowComment = "rkn-guard-allow"

// GuardService — адаптивный щит: считает новые соединения в ядре и банит источник
// на время. Отличие от основной блокировки — не списки, а поведение: ровно то, чего
// не хватало rkn-guard, и то, ради чего написан HUBGuard.
type GuardService struct {
	logger     zerolog.Logger
	cmd        *CommandService
	ConfigPath string
	BansPath   string
	FeedsPath  string
	UnitPath   string
	HTTP       *http.Client
	// TableExists и Peer вынесены в поля, чтобы тесты не зависели от nft и SSH.
	TableExists func(*CommandService) bool
	Peer        func() (netip.Addr, error)
}

// NewGuardService создаёт сервис с путями по умолчанию.
func NewGuardService(logger zerolog.Logger, cmd *CommandService) *GuardService {
	return &GuardService{
		logger:      logger,
		cmd:         cmd,
		ConfigPath:  GuardConfigPath,
		BansPath:    GuardBansPath,
		FeedsPath:   GuardFeedsPath,
		UnitPath:    GuardUnitPath,
		HTTP:        &http.Client{Timeout: 15 * time.Second},
		TableExists: guardTableExists,
		Peer:        GuardPeerIP,
	}
}

// GuardApplyOptions — как применять: показать, применить, переопределить настройки.
type GuardApplyOptions struct {
	DryRun     bool
	Force      bool
	ExtraAllow []string
	Mutate     func(*GuardConfig) error
}

// GuardApplyResult — что реально произошло.
type GuardApplyResult struct {
	Script       string
	Applied      bool
	Allow4       []netip.Prefix
	Allow6       []netip.Prefix
	Feed4        []netip.Prefix
	Feed6        []netip.Prefix
	BanCount     int
	Rate         int
	BanLength    time.Duration
	Peer         netip.Addr
	Ports        []int
	Warnings     []string
	BlockedPeers string
}

// LoadConfig читает настройки щита.
func (s *GuardService) LoadConfig() (*GuardConfig, error) {
	return LoadGuardConfig(s.ConfigPath)
}

// SaveConfig валидирует и пишет настройки.
func (s *GuardService) SaveConfig(cfg *GuardConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	return SaveGuardConfig(s.ConfigPath, cfg)
}

// plan собирает всё, что нужно для применения, ничего не меняя в системе.
func (s *GuardService) plan(opts GuardApplyOptions) (*GuardConfig, GuardRenderInput, *GuardApplyResult, error) {
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return nil, GuardRenderInput{}, nil, err
	}
	if opts.Mutate != nil {
		if err := opts.Mutate(cfg); err != nil {
			return nil, GuardRenderInput{}, nil, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, GuardRenderInput{}, nil, err
	}
	rate, banLength, err := cfg.GuardRate()
	if err != nil {
		return nil, GuardRenderInput{}, nil, err
	}
	result := &GuardApplyResult{Rate: rate, BanLength: banLength, Ports: append([]int(nil), cfg.Ports...)}

	peer, _ := s.callPeer()
	result.Peer = peer
	var extra []netip.Prefix
	if peer.IsValid() {
		// Адрес сессии в белом списке до применения правил, а не после.
		extra = append(extra, netip.PrefixFrom(peer, peer.BitLen()))
	}
	cliAllow, err := ParseGuardAllow(opts.ExtraAllow)
	if err != nil {
		return nil, GuardRenderInput{}, nil, err
	}
	extra = append(extra, cliAllow...)
	allow4, allow6, err := GuardAllowPrefixes(cfg, extra)
	if err != nil {
		return nil, GuardRenderInput{}, nil, err
	}
	allowAll := append(append([]netip.Prefix(nil), allow4...), allow6...)

	feeds, err := SyncGuardFeeds(cfg, allowAll, s.FeedsPath, s.HTTP)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("фиды: %v", err))
	} else {
		result.Warnings = append(result.Warnings, feeds.Warnings...)
		for _, prefix := range feeds.Prefixes {
			if prefix.Addr().Is4() {
				result.Feed4 = append(result.Feed4, prefix)
			} else {
				result.Feed6 = append(result.Feed6, prefix)
			}
		}
	}
	bans, err := LoadGuardBans(s.BansPath)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("сохранённые баны: %v", err))
	}
	result.Allow4, result.Allow6 = allow4, allow6
	result.BanCount = len(bans)

	input := GuardRenderInput{
		Config: cfg,
		Allow4: allow4,
		Allow6: allow6,
		Feed4:  result.Feed4,
		Feed6:  result.Feed6,
		Bans:   bans,
		Exists: s.tableExists(),
		Rate:   rate,
		Ban:    banLength,
	}
	return cfg, input, result, nil
}

// Plan возвращает скрипт, который был бы применён.
func (s *GuardService) Plan(opts GuardApplyOptions) (*GuardApplyResult, error) {
	_, input, result, err := s.plan(opts)
	if err != nil {
		return nil, err
	}
	script, err := RenderGuardRules(input)
	if err != nil {
		return nil, err
	}
	result.Script = script
	return result, nil
}

// Apply проверяет и применяет правила одной транзакцией nft.
func (s *GuardService) Apply(opts GuardApplyOptions) (*GuardApplyResult, error) {
	cfg, input, result, err := s.plan(opts)
	if err != nil {
		return nil, err
	}
	script, err := RenderGuardRules(input)
	if err != nil {
		return nil, err
	}
	result.Script = script

	state, err := LoadFirewall()
	if err != nil {
		return nil, err
	}
	peer := result.Peer
	allowAll := append(append([]netip.Prefix(nil), result.Allow4...), result.Allow6...)

	// Проверка на самострел: если правила отрежут текущую сессию и прикрыть её нечем,
	// лучше отказаться, чем оставить человека без сервера.
	blocked := GuardBlockedPrefixes(s.cmd, state.Backend)
	if risk := GuardSelfLockoutRisk(peer, allowAll, blocked); risk != "" {
		if state.Backend == "iptables" && !opts.Force {
			return nil, fmt.Errorf("%s; в режиме iptables белый список щита не действует на ipset-блокировку. "+
				"Добавьте адрес в исключения (исключения) или примените с --force", risk)
		}
		result.BlockedPeers = risk
		result.Warnings = append(result.Warnings,
			risk+". Адрес добавлен в белый список первым правилом, доступ сохранится")
	}

	if opts.DryRun {
		return result, nil
	}
	if err := runNFT(s.cmd, script); err != nil {
		return nil, fmt.Errorf("nft отклонил правила щита: %w", err)
	}
	result.Applied = true

	// Белый список переносится и в основную блокировку: подсеть из списка сканеров
	// больше не может отрезать администратора.
	if state.Backend != "iptables" {
		if nftTableExists(s.cmd, "rkn_guard") {
			if err := RebuildNFTState(s.cmd, state, allowAll); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf(
					"белый список не перенесён в основную блокировку: %v", err))
			}
		}
	} else if err := s.syncIptablesAllow(result.Allow4, result.Allow6, cfg.Logging); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("белый список не перенесён в iptables: %v", err))
	}

	if err := SaveGuardConfig(s.ConfigPath, cfg); err != nil {
		return nil, fmt.Errorf("правила применены, но настройки не сохранены: %w", err)
	}
	if err := s.InstallUnit(cfg); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("автозапуск не настроен: %v", err))
	}
	return result, nil
}

// Restore применяет сохранённые настройки при загрузке. Щит выключен — тихо ничего не делает.
func (s *GuardService) Restore() (*GuardApplyResult, error) {
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return &GuardApplyResult{}, nil
	}
	return s.Apply(GuardApplyOptions{})
}

// Rollback снимает правила щита и автозапуск. Настройки остаются: включить обратно — одна команда.
func (s *GuardService) Rollback() error {
	if s.tableExists() {
		if err := s.cmd.Run("nft", "delete", "table", "inet", GuardTable); err != nil {
			return fmt.Errorf("не удалось удалить таблицу %s: %w", GuardTable, err)
		}
	}
	if err := s.RemoveUnit(); err != nil {
		return err
	}
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return err
	}
	cfg.Enabled = false
	if err := SaveGuardConfig(s.ConfigPath, cfg); err != nil {
		return err
	}
	// Баны в ядре больше не живут: файл без них, иначе после включения вернутся призраки.
	return SaveGuardBans(s.BansPath, nil)
}

// GuardStatus — состояние щита для челов и для меню.
type GuardStatus struct {
	Configured   bool
	Enabled      bool
	Applied      bool
	Level        string
	Rate         int
	BanLength    time.Duration
	Ports        []int
	IPv6         bool
	Logging      bool
	AllowCount   int
	FeedCount    int
	FeedDisabled int
	Bans         []GuardBan
	Warnings     []string
	Packets      uint64
	Bytes        uint64
	Peer         netip.Addr
}

// Status читает настройки, ядро и баны, ничего не меняя.
func (s *GuardService) Status() (*GuardStatus, error) {
	status := &GuardStatus{}
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return nil, err
	}
	status.Configured = true
	status.Enabled = cfg.Enabled
	status.Level = cfg.Level
	status.Ports = append([]int(nil), cfg.Ports...)
	status.IPv6 = cfg.IPv6
	status.Logging = cfg.Logging
	rate, banLength, rateErr := cfg.GuardRate()
	if rateErr == nil {
		status.Rate, status.BanLength = rate, banLength
	} else {
		status.Warnings = append(status.Warnings, rateErr.Error())
	}
	allow, allowErr := GuardAllowForBlocklist()
	if allowErr != nil {
		status.Warnings = append(status.Warnings, fmt.Sprintf("белый список: %v", allowErr))
	}
	status.AllowCount = len(allow)
	for _, feed := range cfg.Feeds {
		if feed.Enabled {
			status.FeedCount++
		} else {
			status.FeedDisabled++
		}
	}
	status.Peer, _ = s.callPeer()
	status.Applied = s.tableExists()
	if status.Applied {
		v4, _ := kernelGuardBans(s.cmd, "banned4")
		v6, _ := kernelGuardBans(s.cmd, "banned6")
		status.Bans = MergeGuardBans(v4, v6)
		status.Packets, status.Bytes, _ = kernelGuardCounter(s.cmd)
	} else if saved, err := LoadGuardBans(s.BansPath); err == nil {
		status.Bans = saved
	}
	return status, nil
}

// Ban блокирует один адрес вручную: пишет в состояние и сразу в ядро.
func (s *GuardService) Ban(raw string, banLength time.Duration) (netip.Addr, error) {
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return netip.Addr{}, err
	}
	allow4, allow6, err := GuardAllowPrefixes(cfg, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := GuardBanTarget(raw, append(allow4, allow6...))
	if err != nil {
		return netip.Addr{}, err
	}
	if banLength <= 0 {
		_, banLength, err = cfg.GuardRate()
		if err != nil {
			return netip.Addr{}, err
		}
	}
	saved, err := LoadGuardBans(s.BansPath)
	if err != nil {
		return netip.Addr{}, err
	}
	saved = MergeGuardBans(saved, []GuardBan{{Addr: addr, Remaining: banLength}})
	if err := SaveGuardBans(s.BansPath, saved); err != nil {
		return netip.Addr{}, err
	}
	if s.tableExists() {
		set := "banned4"
		if addr.Is6() {
			set = "banned6"
		}
		if err := s.cmd.Run("nft", "add", "element", "inet", GuardTable, set,
			fmt.Sprintf("{ %s timeout %s }", addr, FormatGuardDuration(banLength))); err != nil {
			return netip.Addr{}, fmt.Errorf("%s, но в ядро запись не попала: %w", addr, err)
		}
	}
	return addr, nil
}

// Unban снимает бан и в состоянии, и в ядре.
func (s *GuardService) Unban(raw string) (netip.Addr, bool, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("%q — не адрес", raw)
	}
	addr = addr.Unmap()
	saved, err := LoadGuardBans(s.BansPath)
	if err != nil {
		return netip.Addr{}, false, err
	}
	remaining, removed := DropGuardBan(saved, addr)
	if err := SaveGuardBans(s.BansPath, remaining); err != nil {
		return netip.Addr{}, false, err
	}
	if s.tableExists() {
		set := "banned4"
		if addr.Is6() {
			set = "banned6"
		}
		if err := s.cmd.Run("nft", "delete", "element", "inet", GuardTable, set,
			fmt.Sprintf("{ %s }", addr)); err != nil {
			return addr, removed, nil
		}
	}
	return addr, removed, nil
}

// AllowAdd добавляет адреса и подсети в белый список.
func (s *GuardService) AllowAdd(values []string) ([]netip.Prefix, error) {
	parsed, err := ParseGuardAllow(values)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return nil, err
	}
	existing, err := ParseGuardAllow(cfg.Allow)
	if err != nil {
		return nil, err
	}
	merged := CollapseGuardPrefixes(append(existing, parsed...))
	cfg.Allow = guardPrefixStringsStable(merged)
	if err := SaveGuardConfig(s.ConfigPath, cfg); err != nil {
		return nil, err
	}
	return merged, nil
}

// AllowRemove убирает запись из белого списка.
func (s *GuardService) AllowRemove(value string) (bool, error) {
	target, err := parseGuardPrefix(strings.TrimSpace(value))
	if err != nil {
		return false, err
	}
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return false, err
	}
	existing, err := ParseGuardAllow(cfg.Allow)
	if err != nil {
		return false, err
	}
	kept := make([]netip.Prefix, 0, len(existing))
	removed := false
	for _, prefix := range existing {
		if prefix == target {
			removed = true
			continue
		}
		kept = append(kept, prefix)
	}
	cfg.Allow = guardPrefixStringsStable(kept)
	if err := SaveGuardConfig(s.ConfigPath, cfg); err != nil {
		return false, err
	}
	return removed, nil
}

// SetAllow заменяет белый список целиком.
func (s *GuardService) SetAllow(values []string) ([]netip.Prefix, error) {
	parsed, err := ParseGuardAllow(values)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return nil, err
	}
	cfg.Allow = guardPrefixStringsStable(parsed)
	if err := SaveGuardConfig(s.ConfigPath, cfg); err != nil {
		return nil, err
	}
	return parsed, nil
}

// AddFeed добавляет внешний список адресов.
func (s *GuardService) AddFeed(rawURL string) (GuardFeed, error) {
	url, err := NormalizeSourceURL(rawURL)
	if err != nil {
		return GuardFeed{}, err
	}
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return GuardFeed{}, err
	}
	for _, feed := range cfg.Feeds {
		if feed.URL == url {
			return GuardFeed{}, fmt.Errorf("фид уже добавлен (номер %d)", feed.ID)
		}
	}
	if len(cfg.Feeds) >= guardMaxFeeds {
		return GuardFeed{}, fmt.Errorf("уже %d фидов: это предел", guardMaxFeeds)
	}
	feed := GuardFeed{ID: cfg.NextFeedID, URL: url, Enabled: true}
	cfg.NextFeedID++
	cfg.Feeds = append(cfg.Feeds, feed)
	if err := SaveGuardConfig(s.ConfigPath, cfg); err != nil {
		return GuardFeed{}, err
	}
	return feed, nil
}

// RemoveFeed удаляет фид по номеру.
func (s *GuardService) RemoveFeed(id int) (GuardFeed, error) {
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return GuardFeed{}, err
	}
	for i, feed := range cfg.Feeds {
		if feed.ID != id {
			continue
		}
		cfg.Feeds = append(cfg.Feeds[:i], cfg.Feeds[i+1:]...)
		if err := SaveGuardConfig(s.ConfigPath, cfg); err != nil {
			return GuardFeed{}, err
		}
		return feed, nil
	}
	return GuardFeed{}, fmt.Errorf("фид %d не найден", id)
}

// ToggleFeed включает и выключает фид.
func (s *GuardService) ToggleFeed(id int, enabled bool) (GuardFeed, error) {
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return GuardFeed{}, err
	}
	for i := range cfg.Feeds {
		if cfg.Feeds[i].ID != id {
			continue
		}
		cfg.Feeds[i].Enabled = enabled
		if err := SaveGuardConfig(s.ConfigPath, cfg); err != nil {
			return GuardFeed{}, err
		}
		return cfg.Feeds[i], nil
	}
	return GuardFeed{}, fmt.Errorf("фид %d не найден", id)
}

// DropFeedCache забывает скачанные копии: следующий apply перекачает всё заново.
func (s *GuardService) DropFeedCache() error {
	if err := os.Remove(s.FeedsPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SetEnabled включает и выключает щит в настройках.
func (s *GuardService) SetEnabled(enabled bool) error {
	cfg, err := LoadGuardConfig(s.ConfigPath)
	if err != nil {
		return err
	}
	cfg.Enabled = enabled
	return SaveGuardConfig(s.ConfigPath, cfg)
}

// SyncIptablesAllow переносит белый список в цепочку iptables первым правилом.
func (s *GuardService) syncIptablesAllow(v4, v6 []netip.Prefix, logging bool) error {
	groups := []struct {
		binary  string
		entries []netip.Prefix
	}{{"iptables", v4}, {"ip6tables", v6}}
	changed := false
	for _, group := range groups {
		if len(group.entries) == 0 {
			continue
		}
		current, err := s.cmd.RunOutputQuiet(group.binary, "-S", chainName)
		if err != nil || strings.Contains(current, "No chain") {
			continue
		}
		for _, line := range strings.Split(current, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "-A "+chainName+" ") || !strings.Contains(line, guardAllowComment) {
				continue
			}
			spec := strings.Fields(strings.TrimPrefix(line, "-A "+chainName+" "))
			if err := s.cmd.RunQuiet(group.binary, append([]string{"-D", chainName}, spec...)...); err != nil {
				return err
			}
			changed = true
		}
		for i := len(group.entries) - 1; i >= 0; i-- {
			if err := s.cmd.RunQuiet(group.binary, "-I", chainName, "1", "-s", group.entries[i].String(),
				"-m", "comment", "--comment", guardAllowComment, "-j", "RETURN"); err != nil {
				return err
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	// Правила в цепочке должны пережить перезагрузку теми же механизмами, что и остальные.
	iptablesService := NewIptablesService(s.logger, s.cmd, logging)
	return iptablesService.Save()
}

func (s *GuardService) tableExists() bool {
	if s.TableExists == nil {
		return guardTableExists(s.cmd)
	}
	return s.TableExists(s.cmd)
}

func (s *GuardService) callPeer() (netip.Addr, error) {
	if s.Peer == nil {
		return GuardPeerIP()
	}
	return s.Peer()
}

func guardPrefixStringsStable(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
)

// guardFlags — параметры применения. nil-значения означают «оставить как в настройках»:
// флаг, который не указали, не должен молча переписывать конфиг.
type guardFlags struct {
	level     string
	rate      int
	banTime   string
	ports     []string
	allow     []string
	ipv6      bool
	logging   bool
	enabled   bool
	dryRun    bool
	force     bool
	noIPv6    bool
	noLogging bool
}

func (f *guardFlags) mutate(cmd *cobra.Command) func(*service.GuardConfig) error {
	return func(cfg *service.GuardConfig) error {
		if f.level != "" {
			cfg.Level = f.level
		}
		if f.rate > 0 {
			cfg.Rate = f.rate
		}
		if f.banTime != "" {
			if _, err := service.ParseGuardDuration(f.banTime); err != nil {
				return fmt.Errorf("--ban-time: %w", err)
			}
			cfg.BanTime = f.banTime
		}
		if len(f.ports) > 0 {
			ports, err := service.ParseGuardPorts(f.ports)
			if err != nil {
				return err
			}
			cfg.Ports = ports
		}
		if cmd.Flags().Changed("ipv6") {
			cfg.IPv6 = f.ipv6
		}
		if f.noIPv6 {
			cfg.IPv6 = false
		}
		if cmd.Flags().Changed("logging") {
			cfg.Logging = f.logging
		}
		if f.noLogging {
			cfg.Logging = false
		}
		if cmd.Flags().Changed("enabled") {
			cfg.Enabled = f.enabled
		}
		return nil
	}
}

func bindGuardApplyFlags(cmd *cobra.Command, flags *guardFlags) {
	cmd.Flags().StringVar(&flags.level, "level", "", "Профиль: relaxed, basic, enhanced, strict или custom")
	cmd.Flags().IntVar(&flags.rate, "rate", 0, "Новых соединений в минуту с одного адреса (для --level custom)")
	cmd.Flags().StringVar(&flags.banTime, "ban-time", "", "Срок бана: 30m, 1h, 6h (для --level custom)")
	cmd.Flags().StringSliceVar(&flags.ports, "ports", nil, "Порты через запятую (по умолчанию 443)")
	cmd.Flags().StringSliceVar(&flags.allow, "allow", nil, "Белый список: адреса и подсети через запятую")
	cmd.Flags().BoolVar(&flags.ipv6, "ipv6", true, "Учитывать IPv6 (--ipv6=false выключает)")
	cmd.Flags().BoolVar(&flags.noIPv6, "no-ipv6", false, "Выключить IPv6")
	cmd.Flags().BoolVar(&flags.logging, "logging", true, "Писать в журнал забаненные подключения")
	cmd.Flags().BoolVar(&flags.noLogging, "no-logging", false, "Не писать в журнал забаненные подключения")
	cmd.Flags().BoolVar(&flags.enabled, "enabled", true, "Пометить щит включённым")
	cmd.Flags().BoolVar(&flags.dryRun, "dry-run", false, "Только показать правила")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Применить, даже если адрес сессии под блокировкой")
}

func newGuardCommand() *cobra.Command {
	guardCmd := &cobra.Command{
		Use:   "guard",
		Short: "Адаптивный щит: автобан сканеров по числу новых соединений",
		Long: `Считает новые соединения средствами ядра (conntrack + nftables) и банит источник
на время. Логи не парсится, поэтому работает с любым VPN-ядром.

Своя таблица inet rkn_guard_dynamic, белый список первым правилом, бан только по одному
адресу и всегда со сроком. Откат — одной командой, без следов.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGuardStatus()
		},
	}

	applyFlags := &guardFlags{}
	applyCmd := &cobra.Command{
		Use:   "apply",
		Short: "Проверить и применить правила щита",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			return runGuardApply(applyFlags, cmd, false)
		},
	}
	bindGuardApplyFlags(applyCmd, applyFlags)

	planFlags := &guardFlags{}
	planCmd := &cobra.Command{
		Use:   "plan",
		Short: "Показать правила, которые будут применены (ничего не меняет)",
		Long:  `Печатает скрипт nft и проверяет его синтаксис через nft --check. Правила и firewall не меняются.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			return runGuardApply(planFlags, cmd, true)
		},
	}
	bindGuardApplyFlags(planCmd, planFlags)

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Показать состояние щита",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGuardStatus()
		},
	}

	topCmd := &cobra.Command{
		Use:   "top",
		Short: "Показать, кто сейчас в бане",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGuardTop()
		},
	}

	var banFor string
	banCmd := &cobra.Command{
		Use:   "ban АДРЕС",
		Short: "Забанить один адрес вручную",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			var banLength time.Duration
			if banFor != "" {
				parsed, err := service.ParseGuardDuration(banFor)
				if err != nil {
					return err
				}
				banLength = parsed
			}
			svc, err := newGuardService()
			if err != nil {
				return err
			}
			addr, err := svc.Ban(args[0], banLength)
			if err != nil {
				return err
			}
			fmt.Printf("Забанен %s\n", addr)
			return nil
		},
	}
	banCmd.Flags().StringVar(&banFor, "for", "", "Срок бана (по умолчанию из профиля)")

	unbanCmd := &cobra.Command{
		Use:   "unban АДРЕС",
		Short: "Снять бан с адреса",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			svc, err := newGuardService()
			if err != nil {
				return err
			}
			addr, found, err := svc.Unban(args[0])
			if err != nil {
				return err
			}
			if found {
				fmt.Printf("Снят бан с %s\n", addr)
			} else {
				fmt.Printf("%s не найден в списке банов (в ядре снят)\n", addr)
			}
			return nil
		},
	}

	rollbackCmd := &cobra.Command{
		Use:   "rollback",
		Short: "Снять правила щита и автозапуск одной командой",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			svc, err := newGuardService()
			if err != nil {
				return err
			}
			if err := svc.Rollback(); err != nil {
				return err
			}
			fmt.Println("Щит снят: таблица удалена, автозапуск выключен, баны очищены.")
			return nil
		},
	}

	restoreCmd := &cobra.Command{
		Use:    "restore",
		Short:  "Восстановить правила из настроек (используется при загрузке)",
		Hidden: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			svc, err := newGuardService()
			if err != nil {
				return err
			}
			result, err := svc.Restore()
			if err != nil {
				return err
			}
			printGuardWarnings(result.Warnings)
			if result.Applied {
				fmt.Printf("Щит восстановлен: порты %v, порог %d/мин, бан %s\n",
					result.Ports, result.Rate, service.FormatGuardDuration(result.BanLength))
			}
			return nil
		},
	}

	guardCmd.AddCommand(applyCmd, planCmd, statusCmd, topCmd, banCmd, unbanCmd,
		rollbackCmd, restoreCmd, newGuardAllowCommand(), newGuardFeedCommand())
	return guardCmd
}

func newGuardAllowCommand() *cobra.Command {
	allowCmd := &cobra.Command{
		Use:   "allow",
		Short: "Белый список: адреса и подсети, которые не банятся никогда",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGuardAllowList()
		},
	}
	allowCmd.AddCommand(
		&cobra.Command{
			Use: "list", Short: "Показать белый список",
			RunE: func(cmd *cobra.Command, args []string) error { return runGuardAllowList() },
		},
		&cobra.Command{
			Use: "add АДРЕС...", Short: "Добавить адрес или подсеть", Args: cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := requireRoot(); err != nil {
					return err
				}
				svc, err := newGuardService()
				if err != nil {
					return err
				}
				merged, err := svc.AllowAdd(args)
				if err != nil {
					return err
				}
				fmt.Printf("В белом списке %d записей:\n", len(merged))
				for _, prefix := range merged {
					fmt.Printf("  %s\n", prefix)
				}
				return nil
			},
		},
		&cobra.Command{
			Use: "remove АДРЕС", Short: "Убрать адрес или подсеть", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := requireRoot(); err != nil {
					return err
				}
				svc, err := newGuardService()
				if err != nil {
					return err
				}
				removed, err := svc.AllowRemove(args[0])
				if err != nil {
					return err
				}
				if removed {
					fmt.Println("Удалено из белого списка.")
				} else {
					fmt.Println("Такой записи в белом списке нет.")
				}
				return nil
			},
		},
		&cobra.Command{
			Use: "set АДРЕС...", Short: "Заменить белый список целиком", Args: cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := requireRoot(); err != nil {
					return err
				}
				svc, err := newGuardService()
				if err != nil {
					return err
				}
				parsed, err := svc.SetAllow(args)
				if err != nil {
					return err
				}
				fmt.Printf("Белый список заменён: %d записей\n", len(parsed))
				return nil
			},
		},
	)
	return allowCmd
}

func newGuardFeedCommand() *cobra.Command {
	feedCmd := &cobra.Command{
		Use:   "feed",
		Short: "Внешние списки адресов (только отдельные адреса и узкие подсети)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGuardFeedList()
		},
	}
	feedCmd.AddCommand(
		&cobra.Command{
			Use: "list", Short: "Показать фиды",
			RunE: func(cmd *cobra.Command, args []string) error { return runGuardFeedList() },
		},
		&cobra.Command{
			Use: "add URL", Short: "Добавить фид", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := requireRoot(); err != nil {
					return err
				}
				svc, err := newGuardService()
				if err != nil {
					return err
				}
				feed, err := svc.AddFeed(args[0])
				if err != nil {
					return err
				}
				fmt.Printf("Добавлен фид %d: %s\n", feed.ID, feed.URL)
				fmt.Println("Примените правила: rkn-guard guard apply")
				return nil
			},
		},
		&cobra.Command{
			Use: "remove НОМЕР", Short: "Удалить фид", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := requireRoot(); err != nil {
					return err
				}
				id, err := parseFeedID(args[0])
				if err != nil {
					return err
				}
				svc, err := newGuardService()
				if err != nil {
					return err
				}
				feed, err := svc.RemoveFeed(id)
				if err != nil {
					return err
				}
				fmt.Printf("Удалён фид %d: %s\n", feed.ID, feed.URL)
				return nil
			},
		},
		&cobra.Command{
			Use: "enable НОМЕР", Short: "Включить фид", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return toggleGuardFeed(args[0], true)
			},
		},
		&cobra.Command{
			Use: "disable НОМЕР", Short: "Выключить фид", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return toggleGuardFeed(args[0], false)
			},
		},
		&cobra.Command{
			Use: "refresh", Short: "Скачать фиды заново при следующем применении",
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := requireRoot(); err != nil {
					return err
				}
				svc, err := newGuardService()
				if err != nil {
					return err
				}
				if err := svc.DropFeedCache(); err != nil {
					return err
				}
				fmt.Println("Кеш фидов очищен.")
				return nil
			},
		},
	)
	return feedCmd
}

func runGuardApply(flags *guardFlags, cmd *cobra.Command, planOnly bool) error {
	svc, err := newGuardService()
	if err != nil {
		return err
	}
	opts := service.GuardApplyOptions{
		DryRun:     planOnly || flags.dryRun,
		Force:      flags.force,
		ExtraAllow: flags.allow,
		Mutate:     flags.mutate(cmd),
	}
	if opts.DryRun {
		result, err := svc.Plan(opts)
		if err != nil {
			return err
		}
		fmt.Print(result.Script)
		printGuardWarnings(result.Warnings)
		// Итог — в stderr: stdout остаётся чистым скриптом, который можно скормить nft.
		fmt.Fprintf(os.Stderr, "\nВсего: порог %d новых соединений в минуту, бан %s, запрет подсетями не используется.\n",
			result.Rate, service.FormatGuardDuration(result.BanLength))
		return nil
	}
	result, err := svc.Apply(opts)
	if err != nil {
		return err
	}
	printGuardWarnings(result.Warnings)
	cfg, err := svc.LoadConfig()
	if err == nil {
		fmt.Printf("Щит применён: профиль %s, порог %d/мин, бан %s, порты %v\n",
			cfg.Level, result.Rate, service.FormatGuardDuration(result.BanLength), cfg.Ports)
	}
	fmt.Printf("Белый список: %d подсетей (включая %d IPv6), фиды: %d, ручных банов: %d\n",
		len(result.Allow4)+len(result.Allow6), len(result.Allow6), len(result.Feed4)+len(result.Feed6), result.BanCount)
	if result.Peer.IsValid() {
		fmt.Printf("Адрес текущей сессии: %s (в белом списке)\n", result.Peer)
	}
	return nil
}

func runGuardStatus() error {
	svc, err := newGuardService()
	if err != nil {
		return err
	}
	status, err := svc.Status()
	if err != nil {
		return err
	}
	if !status.Configured {
		fmt.Println("Щит не настроен. Включить: rkn-guard guard apply --level enhanced")
		return nil
	}
	state := "выключен"
	if status.Enabled {
		state = "включён"
	}
	applied := "правила не применены"
	if status.Applied {
		applied = "правила в ядре"
	}
	fmt.Printf("Адаптивный щит: %s, %s\n", state, applied)
	if status.Rate > 0 {
		line := fmt.Sprintf("Профиль: %s — больше %d новых соединений в минуту с одного адреса, бан %s",
			status.Level, status.Rate, service.FormatGuardDuration(status.BanLength))
		if !status.Enabled {
			line = fmt.Sprintf("Настройки в запасе: профиль %s, порог %d/мин, бан %s",
				status.Level, status.Rate, service.FormatGuardDuration(status.BanLength))
		}
		fmt.Println(line)
	}
	fmt.Printf("Порты: %v, IPv6: %v, журнал: %v\n", status.Ports, status.IPv6, status.Logging)
	fmt.Printf("Белый список: %d записей, фиды: %d включено / %d выключено\n",
		status.AllowCount, status.FeedCount, status.FeedDisabled)
	if status.Peer.IsValid() {
		fmt.Printf("Адрес текущей сессии: %s\n", status.Peer)
	}
	if status.Applied {
		fmt.Printf("В бане сейчас: %d\n", len(status.Bans))
		if status.Packets > 0 {
			fmt.Printf("Отброшено щитом: %d пакетов, %s\n", status.Packets, formatBytes(status.Bytes))
		}
	}
	printGuardWarnings(status.Warnings)
	if len(status.Bans) > 0 {
		fmt.Println("Баны (ближайшие к истечению):")
		printGuardBans(status.Bans)
	}
	return nil
}

func runGuardTop() error {
	svc, err := newGuardService()
	if err != nil {
		return err
	}
	status, err := svc.Status()
	if err != nil {
		return err
	}
	if len(status.Bans) == 0 {
		fmt.Println("В бане никого нет.")
		return nil
	}
	printGuardBans(status.Bans)
	return nil
}

func runGuardAllowList() error {
	cfg, err := service.LoadGuardConfig(service.GuardConfigPath)
	if err != nil {
		return err
	}
	v4, v6, err := service.GuardAllowPrefixes(cfg, nil)
	if err != nil {
		return err
	}
	configured, err := service.ParseGuardAllow(cfg.Allow)
	if err != nil {
		return err
	}
	fmt.Println("Свои записи:")
	if len(configured) == 0 {
		fmt.Println("  (нет)")
	}
	for _, prefix := range configured {
		fmt.Printf("  %s\n", prefix)
	}
	fmt.Println("Действует с учётом встроенных и адреса сессии:")
	for _, prefix := range v4 {
		fmt.Printf("  %s\n", prefix)
	}
	for _, prefix := range v6 {
		fmt.Printf("  %s\n", prefix)
	}
	return nil
}

func runGuardFeedList() error {
	cfg, err := service.LoadGuardConfig(service.GuardConfigPath)
	if err != nil {
		return err
	}
	if len(cfg.Feeds) == 0 {
		fmt.Println("Фидов нет.")
		return nil
	}
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "НОМЕР\tВКЛ\tURL")
	for _, feed := range cfg.Feeds {
		enabled := "нет"
		if feed.Enabled {
			enabled = "да"
		}
		fmt.Fprintf(writer, "%d\t%s\t%s\n", feed.ID, enabled, feed.URL)
	}
	return writer.Flush()
}

func toggleGuardFeed(rawID string, enabled bool) error {
	if err := requireRoot(); err != nil {
		return err
	}
	id, err := parseFeedID(rawID)
	if err != nil {
		return err
	}
	svc, err := newGuardService()
	if err != nil {
		return err
	}
	feed, err := svc.ToggleFeed(id, enabled)
	if err != nil {
		return err
	}
	state := "выключен"
	if feed.Enabled {
		state = "включён"
	}
	fmt.Printf("Фид %d %s: %s\n", feed.ID, state, feed.URL)
	fmt.Println("Примените правила: rkn-guard guard apply")
	return nil
}

func printGuardBans(bans []service.GuardBan) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "АДРЕС\tОСТАЛОСЬ")
	for _, ban := range bans {
		remaining := "до перезагрузки"
		if ban.Remaining > 0 {
			remaining = service.FormatGuardDuration(ban.Remaining.Round(time.Minute))
		}
		fmt.Fprintf(writer, "%s\t%s\n", ban.Addr, remaining)
	}
	writer.Flush()
}

func printGuardWarnings(warnings []string) {
	for _, warning := range warnings {
		fmt.Fprintf(os.Stderr, "Внимание: %s\n", warning)
	}
}

func newGuardService() (*service.GuardService, error) {
	log := logger.Global()
	return service.NewGuardService(log.Logger, service.NewCommandService(log.Logger)), nil
}

func requireRoot() error {
	return service.NewInstallerService(logger.Global().Logger).CheckRootPrivileges()
}

func parseFeedID(raw string) (int, error) {
	var id int
	if _, err := fmt.Sscanf(raw, "%d", &id); err != nil || id < 1 {
		return 0, fmt.Errorf("%q — не номер фида", raw)
	}
	return id, nil
}

func formatBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d Б", value)
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ"}
	size := float64(value)
	index := -1
	for size >= unit && index < len(units)-1 {
		size /= unit
		index++
	}
	return fmt.Sprintf("%.1f %s", size, units[index])
}

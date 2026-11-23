package service

import (
	"fmt"
	"os"
)

// guardUnitContent — юнит восстановления щита после перезагрузки. Отдельный юнит,
// а не строка в чужом: снять щит можно, удалив ровно один файл.
const guardUnitContent = `[Unit]
Description=rkn-guard adaptive guard
DefaultDependencies=no
After=local-fs.target nftables.service firewalld.service
Before=network-pre.target
Wants=network-pre.target
ConditionPathExists=/etc/rkn-guard/guard.json

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rkn-guard guard restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

// InstallUnit ставит юнит автозапуска и включает его.
func (s *GuardService) InstallUnit(cfg *GuardConfig) error {
	data := []byte(guardUnitContent)
	if current, err := os.ReadFile(s.UnitPath); err == nil && string(current) == string(data) {
		if s.cmd.IsServiceEnabled("rkn-guard-guard.service") {
			return nil
		}
	} else if err := atomicWriteFile(s.UnitPath, data, 0644); err != nil {
		return err
	}
	if err := s.cmd.DaemonReload(); err != nil {
		return err
	}
	return s.cmd.EnableService("rkn-guard-guard.service")
}

// RemoveUnit выключает и удаляет юнит автозапуска.
func (s *GuardService) RemoveUnit() error {
	if !s.cmd.CommandExists("systemctl") {
		return nil
	}
	if s.cmd.IsServiceEnabled("rkn-guard-guard.service") {
		if err := s.cmd.DisableService("rkn-guard-guard.service"); err != nil {
			return fmt.Errorf("не удалось выключить автозапуск щита: %w", err)
		}
	}
	if _, err := os.Stat(s.UnitPath); err == nil {
		if err := os.Remove(s.UnitPath); err != nil {
			return err
		}
		return s.cmd.DaemonReload()
	}
	return nil
}

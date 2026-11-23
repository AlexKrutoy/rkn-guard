package service

import (
	"net/netip"
	"testing"
)

func prefixes(raw ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, item := range raw {
		out = append(out, netip.MustParsePrefix(item))
	}
	return out
}

// Если адрес сессии попадёт под новые правила, щит обязан отказаться от применения.
func TestGuardSelfLockoutBlocksPeerInsideBannedSet(t *testing.T) {
	peer := netip.MustParseAddr("198.51.100.20")
	reason := GuardSelfLockoutRisk(peer, prefixes("10.0.0.0/8"), prefixes("198.51.100.0/24"))
	if reason == "" {
		t.Fatal("ожидался отказ: адрес сессии внутри заблокированной подсети")
	}
}

// Если адрес сессии не попадает ни в одну блокируемую подсеть, отказ не нужен:
// в белый список он всё равно попадает до применения правил.
func TestGuardSelfLockoutClearWhenPeerOutsideBlockedSet(t *testing.T) {
	peer := netip.MustParseAddr("198.51.100.20")
	reason := GuardSelfLockoutRisk(peer, prefixes("10.0.0.0/8"), prefixes("203.0.113.0/24"))
	if reason != "" {
		t.Fatalf("риск не должен возникать: %s", reason)
	}
}

// Неопределённый адрес сессии не должен ломать проверку.
func TestGuardSelfLockoutIgnoresInvalidPeer(t *testing.T) {
	if reason := GuardSelfLockoutRisk(netip.Addr{}, nil, prefixes("0.0.0.0/0")); reason != "" {
		t.Fatalf("для невалидного адреса ожидалась пустая причина, получено: %s", reason)
	}
}

// Адрес в белом списке — риск исключён, отказ не нужен.
func TestGuardSelfLockoutClearWhenPeerAllowed(t *testing.T) {
	peer := netip.MustParseAddr("198.51.100.20")
	reason := GuardSelfLockoutRisk(peer, prefixes("10.0.0.0/8", "198.51.100.20/32"), prefixes("203.0.113.0/24"))
	if reason != "" {
		t.Fatalf("риск не должен возникать: %s", reason)
	}
}

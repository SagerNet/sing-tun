package tun

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-tun/internal/winfw"

	"golang.org/x/sys/windows"
)

func fixWindowsFirewall() error {
	absPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return err
	}
	rule := winfw.FWRule{
		Name:            "sing-tun (" + absPath + ")",
		ApplicationName: absPath,
		Enabled:         true,
		Protocol:        winfw.NET_FW_IP_PROTOCOL_TCP,
		Profiles:        winfw.NET_FW_PROFILE2_PRIVATE,
		Direction:       winfw.NET_FW_RULE_DIR_IN,
		Action:          winfw.NET_FW_ACTION_ALLOW,
	}
	_, err = winfw.FirewallRuleAddAdvanced(rule)
	return err
}

func retryableListenError(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL)
}

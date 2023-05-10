package tun

import (
	"os"
	"os/exec"
	"path/filepath"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/shell"
)

func fixWindowsFirewall() error {
	const shellStringSplit = "\""
	isPWSH := true
	powershell, err := exec.LookPath("pwsh.exe")
	if err != nil {
		powershell, err = exec.LookPath("powershell.exe")
		isPWSH = false
	}
	if err != nil {
		return err
	}
	ruleName := "sing-tun rule for " + os.Args[0]
	commandPrefix := []string{"-NoProfile", "-NonInteractive"}
	if isPWSH {
		commandPrefix = append(commandPrefix, "-Command")
	}
	err = shell.Exec(powershell, append(commandPrefix,
		F.ToString("Get-NetFirewallRule -Name ", shellStringSplit, ruleName, shellStringSplit))...).Run()
	if err == nil {
		return nil
	}
	fileName := filepath.Base(os.Args[0])
	output, err := shell.Exec(powershell, append(commandPrefix,
		F.ToString("New-NetFirewallRule",
			" -Name ", shellStringSplit, ruleName, shellStringSplit,
			" -DisplayName ", shellStringSplit, "sing-tun (", fileName, ")", shellStringSplit,
			" -Program ", shellStringSplit, os.Args[0], shellStringSplit,
			" -Direction Inbound",
			" -Protocol TCP",
			" -Action Allow"))...).Read()
	if err != nil {
		return E.Extend(err, output)
	}
	return nil
}

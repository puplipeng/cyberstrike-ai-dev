//go:build windows

package sshclient

import (
	"errors"

	"golang.org/x/sys/windows"
)

func securePath(path string, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
		return nil
	}
	return err
}

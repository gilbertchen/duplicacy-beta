// Copyright (c) Acrosync LLC. All rights reserved.
// Free for personal use and commercial trial
// Commercial use requires per-user licenses available from https://duplicacy.com

package duplicacy

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type symbolicLinkReparseBuffer struct {
	SubstituteNameOffset uint16
	SubstituteNameLength uint16
	PrintNameOffset      uint16
	PrintNameLength      uint16
	Flags                uint32
	PathBuffer           [1]uint16
}

type mountPointReparseBuffer struct {
	SubstituteNameOffset uint16
	SubstituteNameLength uint16
	PrintNameOffset      uint16
	PrintNameLength      uint16
	PathBuffer           [1]uint16
}

type reparseDataBuffer struct {
	ReparseTag        uint32
	ReparseDataLength uint16
	Reserved          uint16

	// GenericReparseBuffer
	reparseBuffer byte
}

const (
	FSCTL_GET_REPARSE_POINT          = 0x900A8
	MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16 * 1024
	IO_REPARSE_TAG_MOUNT_POINT       = 0xA0000003
	IO_REPARSE_TAG_SYMLINK           = 0xA000000C
	IO_REPARSE_TAG_DEDUP             = 0x80000013
	SYMBOLIC_LINK_FLAG_DIRECTORY     = 0x1

	FILE_READ_ATTRIBUTES                 = 0x00000080
	FILE_ATTRIBUTE_OFFLINE               = 0x00001000
	FILE_ATTRIBUTE_RECALL_ON_OPEN        = 0x00040000
	FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
)

// We copied golang source code for Readlink but made a simple modification here:  use FILE_READ_ATTRIBUTES instead of
// GENERIC_READ to read the symlink, because the latter would cause a Access Denied error on links such as
// C:\Documents and Settings

// Readlink returns the destination of the named symbolic link.
func Readlink(path string) (isRegular bool, s string, err error) {
	fd, err := syscall.CreateFile(syscall.StringToUTF16Ptr(path), FILE_READ_ATTRIBUTES,
		syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false, "", err
	}
	defer syscall.CloseHandle(fd)

	rdbbuf := make([]byte, syscall.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var bytesReturned uint32
	err = syscall.DeviceIoControl(fd, syscall.FSCTL_GET_REPARSE_POINT, nil, 0, &rdbbuf[0],
		uint32(len(rdbbuf)), &bytesReturned, nil)
	if err != nil {
		return false, "", err
	}

	rdb := (*reparseDataBuffer)(unsafe.Pointer(&rdbbuf[0]))
	switch rdb.ReparseTag {
	case IO_REPARSE_TAG_SYMLINK:
		data := (*symbolicLinkReparseBuffer)(unsafe.Pointer(&rdb.reparseBuffer))
		p := (*[0xffff]uint16)(unsafe.Pointer(&data.PathBuffer[0]))
		if data.PrintNameLength > 0 {
			s = syscall.UTF16ToString(p[data.PrintNameOffset/2 : (data.PrintNameLength+data.PrintNameOffset)/2])
		} else {
			s = syscall.UTF16ToString(p[data.SubstituteNameOffset/2 : (data.SubstituteNameLength+data.SubstituteNameOffset)/2])
		}
	case IO_REPARSE_TAG_MOUNT_POINT:
		data := (*mountPointReparseBuffer)(unsafe.Pointer(&rdb.reparseBuffer))
		p := (*[0xffff]uint16)(unsafe.Pointer(&data.PathBuffer[0]))
		if data.PrintNameLength > 0 {
			s = syscall.UTF16ToString(p[data.PrintNameOffset/2 : (data.PrintNameLength+data.PrintNameOffset)/2])
		} else {
			s = syscall.UTF16ToString(p[data.SubstituteNameOffset/2 : (data.SubstituteNameLength+data.SubstituteNameOffset)/2])
		}
	case IO_REPARSE_TAG_DEDUP:
		return true, "", nil
	default:
		// the path is not a symlink or junction but another type of reparse
		// point
		return false, "", fmt.Errorf("Unhandled reparse point type %x", rdb.ReparseTag)
	}

	return false, s, nil
}

func GetOwner(entry *Entry, fileInfo *os.FileInfo) {
	entry.UID = -1
	entry.GID = -1
}

func SetOwner(fullPath string, entry *Entry, fileInfo *os.FileInfo) bool {
	return true
}

func (entry *Entry) ReadAttributes(top string) {
}

func (entry *Entry) SetAttributesToFile(fullPath string) {

}

// IsOffline returns true if the file attributes indicate that the file is currently offline. Returns false otherwise.
func (entry *Entry) IsOffline(fileInfo os.FileInfo) bool {
	sys := fileInfo.Sys().(*syscall.Win32FileAttributeData)
	offline := (sys.FileAttributes & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN)) != 0
	if offline {
		LOG_TRACE("FILE_ATTRIBUTES", "0x%08x %s", sys.FileAttributes, entry.Path)
	}

	return offline
}

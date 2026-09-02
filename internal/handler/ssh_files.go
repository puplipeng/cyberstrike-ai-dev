package handler

import (
	"context"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
	"unicode"

	"cyberstrike-ai/internal/sshclient"
	"github.com/gin-gonic/gin"
	"github.com/pkg/sftp"
)

const sshMaxFile = 16 << 20

// Context cancellation alone cannot interrupt a Request.Body read. Bind both
// the operation deadline and early cancellation to the HTTP transport.
func sshUploadDeadline(c *gin.Context, ctx context.Context) (func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, sshclient.ErrInvalid
	}
	control := http.NewResponseController(c.Writer)
	if err := control.SetReadDeadline(deadline); err != nil {
		return nil, err // fail closed if a wrapper cannot enforce the budget
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(finished)
		_ = control.SetReadDeadline(time.Now())
	})
	return func() {
		if !stop() {
			<-finished
		}
		// Only a normally completed request may reuse its HTTP connection.
		// Keep an expired deadline in place on cancellation.
		if ctx.Err() == nil {
			_ = control.SetReadDeadline(time.Time{})
		}
	}, nil
}

func sshPath(value string) (string, error) {
	if value == "" {
		value = "."
	}
	if len(value) > 4096 || strings.ContainsFunc(value, unicode.IsControl) {
		return "", sshclient.ErrInvalid
	}
	return path.Clean(value), nil
}

type sshFile struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Directory bool   `json:"directory"`
	Mode      string `json:"mode"`
	Modified  string `json:"modified"`
}

func (h *SSHHandler) Files(c *gin.Context) {
	action := c.Param("action")
	if !((c.Request.Method == http.MethodGet && (action == "list" || action == "download")) || (c.Request.Method == http.MethodPost && action == "upload")) {
		c.JSON(405, gin.H{"error": "不支持的文件操作"})
		return
	}
	item, s, ok := h.connection(c, "webshell:write")
	if !ok {
		return
	}
	remote, err := sshPath(c.Query("path"))
	if err != nil {
		h.fail(c, err)
		return
	}
	ctx, done, ok := h.begin(c, item, s, 45*time.Second)
	if !ok {
		return
	}
	defer done()
	if action == "upload" {
		finishRead, err := sshUploadDeadline(c, ctx)
		if err != nil {
			h.fail(c, err)
			return
		}
		defer finishRead()
		if c.Request.ContentLength > sshMaxFile {
			c.JSON(413, gin.H{"error": "单文件最大 16 MiB"})
			return
		}
		if remote == "." || strings.HasSuffix(c.Query("path"), "/") {
			h.fail(c, sshclient.ErrInvalid)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, sshMaxFile)
	}
	client, closeClient, err := h.dial(ctx, item)
	if err != nil {
		h.fail(c, err)
		return
	}
	defer closeClient()
	detail := map[string]interface{}{"path": remote}
	if action == "list" {
		entries, truncated, err := sshclient.ReadDirBounded(ctx, client, remote)
		if err != nil {
			h.record(c, "file_list", item.ID, err, detail)
			h.fail(c, err)
			return
		}
		result := make([]sshFile, 0, len(entries))
		for _, entry := range entries {
			result = append(result, sshFile{entry.Name(), entry.Size(), entry.IsDir(), entry.Mode().String(), entry.ModTime().UTC().Format(time.RFC3339)})
		}
		h.record(c, "file_list", item.ID, nil, detail)
		c.Header("Cache-Control", "no-store")
		c.JSON(200, gin.H{"path": remote, "items": result, "truncated": truncated})
		return
	}
	files, err := sftp.NewClient(client, sftp.MaxConcurrentRequestsPerFile(4))
	if err != nil {
		h.record(c, "files", item.ID, err, nil)
		h.fail(c, err)
		return
	}
	defer files.Close()
	switch action {
	case "download":
		var file *sftp.File
		file, err = files.Open(remote)
		if err == nil {
			defer file.Close()
			var info os.FileInfo
			info, err = file.Stat()
			if err == nil && (!info.Mode().IsRegular() || info.Size() > sshMaxFile) {
				err = sshclient.ErrInvalid
			}
			if err == nil {
				var data []byte
				data, err = io.ReadAll(io.LimitReader(file, sshMaxFile+1))
				if len(data) > sshMaxFile {
					err = sshclient.ErrInvalid
				}
				if err == nil {
					detail["bytes"] = len(data)
					h.record(c, "file_download", item.ID, nil, detail)
					c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(remote)}))
					c.Header("Cache-Control", "no-store")
					c.Header("X-Content-Type-Options", "nosniff")
					c.Data(200, "application/octet-stream", data)
					return
				}
			}
		}
	case "upload":
		var file *sftp.File
		// Never truncate an existing remote file; the user chooses a new filename.
		file, err = files.OpenFile(remote, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err == nil {
			_ = file.Chmod(0600)
			var size int64
			// Do not use SFTP's ReaderFrom, which treats ErrUnexpectedEOF as
			// normal EOF. Preserve HTTP body errors and the declared length.
			size, err = io.Copy(struct{ io.Writer }{file}, c.Request.Body)
			if err == nil && c.Request.ContentLength >= 0 && size != c.Request.ContentLength {
				err = io.ErrUnexpectedEOF
			}
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				_ = files.Remove(remote)
			} else {
				detail["bytes"] = size
				h.record(c, "file_upload", item.ID, nil, detail)
				c.JSON(201, gin.H{"ok": true, "bytes": size})
				return
			}
		} else {
			h.record(c, "file_upload", item.ID, err, detail)
			c.JSON(409, gin.H{"error": "无法创建文件；同名文件不会覆盖，请换一个名称或检查远程目录权限"})
			return
		}
	default:
		err = sshclient.ErrInvalid
	}
	h.record(c, "file_"+action, item.ID, err, detail)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	h.fail(c, err)
}

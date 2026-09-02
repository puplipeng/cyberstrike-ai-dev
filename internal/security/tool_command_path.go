package security

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const cyberStrikeToolPathEnv = "CYBERSTRIKE_TOOL_PATH"

func toolRuntimeSearchDirs() []string {
	var dirs []string
	if raw := strings.TrimSpace(os.Getenv(cyberStrikeToolPathEnv)); raw != "" {
		dirs = append(dirs, filepath.SplitList(raw)...)
	}
	var roots []string
	if exe, err := os.Executable(); err == nil {
		cursor := filepath.Dir(exe)
		for depth := 0; depth < 6; depth++ {
			roots = append(roots, filepath.Join(cursor, "runtime", "security-tools"))
			parent := filepath.Dir(cursor)
			if parent == cursor {
				break
			}
			cursor = parent
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		cursor := cwd
		for depth := 0; depth < 6; depth++ {
			roots = append(roots, filepath.Join(cursor, "runtime", "security-tools"))
			parent := filepath.Dir(cursor)
			if parent == cursor {
				break
			}
			cursor = parent
		}
	}
	for _, root := range roots {
		dirs = append(dirs, root)
		if entries, err := os.ReadDir(filepath.Join(root, "venvs")); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				venvRoot := filepath.Join(root, "venvs", entry.Name())
				dirs = append(dirs,
					venvRoot,
					filepath.Join(venvRoot, "Scripts"),
					filepath.Join(venvRoot, "bin"),
				)
			}
		}
		dirs = append(dirs,
			filepath.Join(root, "bin"),
			filepath.Join(root, "python"),
			filepath.Join(root, "python", "Scripts"),
			filepath.Join(root, "python311"),
			filepath.Join(root, "python311", "Scripts"),
			filepath.Join(root, "python312"),
			filepath.Join(root, "python312", "Scripts"),
			filepath.Join(root, "nmap"),
		)
	}
	seen := make(map[string]struct{}, len(dirs))
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		dir = filepath.Clean(strings.TrimSpace(dir))
		if dir == "." || dir == "" {
			continue
		}
		key := strings.ToLower(dir)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, dir)
	}
	return out
}

func managedToolRuntimeRoot() string {
	for _, dir := range toolRuntimeSearchDirs() {
		if strings.EqualFold(filepath.Base(dir), "security-tools") {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				return dir
			}
		}
	}
	return ""
}

func executableCandidates(command string) []string {
	if runtime.GOOS != "windows" || filepath.Ext(command) != "" {
		return []string{command}
	}
	return []string{command + ".exe", command + ".com", command + ".cmd", command + ".bat", command}
}

func resolveToolCommand(command string) (string, bool) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", false
	}
	if strings.HasPrefix(command, "internal:") {
		return command, true
	}
	if path, ok := preferredManagedPythonCommand(command); ok {
		return path, true
	}
	if filepath.IsAbs(command) || strings.ContainsAny(command, `/\\`) {
		if info, err := os.Stat(command); err == nil && !info.IsDir() {
			return command, true
		}
		return command, false
	}

	searchNames := []string{command}
	if runtime.GOOS == "windows" && strings.EqualFold(command, "python3") {
		// The Microsoft Store python3 alias is often a zero-function stub. Prefer a
		// real python.exe or the platform-managed virtual environment.
		searchNames = []string{"python", "python3"}
	}
	for _, dir := range toolRuntimeSearchDirs() {
		for _, name := range searchNames {
			for _, candidate := range executableCandidates(name) {
				path := filepath.Join(dir, candidate)
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					return path, true
				}
			}
		}
	}
	for _, name := range searchNames {
		if path, err := exec.LookPath(name); err == nil {
			return path, true
		}
	}
	return command, false
}

func preferredManagedPythonCommand(command string) (string, bool) {
	if !(runtime.GOOS == "windows" && (strings.EqualFold(command, "python") || strings.EqualFold(command, "python3"))) {
		return "", false
	}
	root := managedToolRuntimeRoot()
	if root == "" {
		return "", false
	}
	for _, candidate := range []string{
		filepath.Join(root, "venvs", "pytools", "Scripts", "python.exe"),
		filepath.Join(root, "venvs", "pytools", "bin", "python3"),
		filepath.Join(root, "venvs", "pytools", "bin", "python"),
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

func pythonModuleAvailable(pythonCommand, module string) bool {
	module = strings.TrimSpace(module)
	if module == "" {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonCommand, "-c", "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 1)", module)
	cmd.Env = applyManagedToolStateEnv(appendToolRuntimePath(os.Environ()))
	return cmd.Run() == nil
}

func appendToolRuntimePath(env []string) []string {
	dirs := toolRuntimeSearchDirs()
	if len(dirs) == 0 {
		return env
	}
	pathValue := os.Getenv("PATH")
	for i, entry := range env {
		if strings.EqualFold(strings.SplitN(entry, "=", 2)[0], "PATH") {
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) == 2 {
				pathValue = parts[1]
			}
			env = append(env[:i], env[i+1:]...)
			break
		}
	}
	pathValue = strings.Join(append(dirs, pathValue), string(os.PathListSeparator))
	return append(env, "PATH="+pathValue)
}

func setEnvValue(env []string, key, value string) []string {
	for i, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], key) {
			env[i] = key + "=" + value
			return env
		}
	}
	return append(env, key+"="+value)
}

// applyManagedToolStateEnv keeps scanner caches/configuration beside the D-drive
// runtime instead of writing into a service account's AppData profile.
func applyManagedToolStateEnv(env []string) []string {
	root := managedToolRuntimeRoot()
	if root == "" {
		return env
	}
	stateRoot := filepath.Join(root, "state")
	configDir := filepath.Join(stateRoot, "config")
	cacheDir := filepath.Join(stateRoot, "cache")
	if runtime.GOOS == "windows" {
		roamingDir := filepath.Join(stateRoot, "roaming")
		localDir := filepath.Join(stateRoot, "local")
		for _, dir := range []string{configDir, cacheDir, roamingDir, localDir} {
			_ = os.MkdirAll(dir, 0o755)
		}
		env = setEnvValue(env, "APPDATA", roamingDir)
		env = setEnvValue(env, "LOCALAPPDATA", localDir)
	} else {
		_ = os.MkdirAll(configDir, 0o755)
		_ = os.MkdirAll(cacheDir, 0o755)
	}
	env = setEnvValue(env, "XDG_CONFIG_HOME", configDir)
	env = setEnvValue(env, "XDG_CACHE_HOME", cacheDir)
	env = setEnvValue(env, "TRIVY_CACHE_DIR", filepath.Join(cacheDir, "trivy"))
	return env
}

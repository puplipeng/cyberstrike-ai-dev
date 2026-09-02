package skillpackage

import (
	"fmt"
	"os"
)

// OpenSkillRoot confines subsequent filesystem operations to one real skill
// directory, including when a resource contains a symlink or is renamed.
func OpenSkillRoot(skillsRoot, skillID string) (*os.Root, error) {
	if err := ValidateAgentSkillManifest(&SkillManifest{Name: skillID, Description: "path validation"}); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(skillsRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(skillID)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("skill must be a real directory")
	}
	return root.OpenRoot(skillID)
}

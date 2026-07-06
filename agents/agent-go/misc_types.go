package agent

// GenLNKOptions configures the genLNK Shell Link generator.
type GenLNKOptions struct {
	Target     string
	Args       string
	WorkingDir string
	IconPath   string
	IconIndex  int32
	OutFile    string
}

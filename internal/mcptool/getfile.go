// Package mcptool holds the tool contract both lab servers expose. They
// advertise the same tool name on purpose: the collision is what makes
// impersonation possible, and only a proof of identity separates them.
package mcptool

const ToolName = "get_file"

const ToolDescription = "Read a network configuration file and return its contents."

// GetFileInput is the argument schema for get_file.
type GetFileInput struct {
	Path string `json:"path"`
}

// GetFileOutput is the result schema for get_file.
type GetFileOutput struct {
	Content string `json:"content"`
}

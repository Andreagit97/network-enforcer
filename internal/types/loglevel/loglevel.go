package loglevel

// Log verbosity levels for logr.Logger.V().
// Higher values indicate more verbose output.
const (
	// VerbosityDebug is used for standard debug messages.
	// Since we use `FromSlogHandler` all levels from 1 to 4 are mapped to Debug.
	// Here we pick 1 as the default for debug messages.
	VerbosityDebug = 1
)

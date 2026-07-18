// Package log configures the global zerolog logger for horchestra's binaries.
package log

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Setup configures the global zerolog logger: it sets the global level from a
// level string ("debug", "info", "warn", ...), defaulting to info when empty or
// unrecognized, and writes to stderr as human-readable console output when pretty
// or JSON otherwise.
func Setup(level string, pretty bool) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil || len(level) == 0 {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)
	if pretty {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
		return
	}
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
}

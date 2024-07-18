package outputhandler

import (
	"github.com/openvex/go-vex/pkg/vex"
)

type OutputHandler interface {
	HandleStatements([]vex.Statement) error
	Close() error
}

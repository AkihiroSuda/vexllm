package outputhandler

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/openvex/go-vex/pkg/vex"
)

type trivyignoreOutputHandler struct {
	w io.WriteCloser
}

func NewTrivyignoreOutputHandler(w io.WriteCloser) OutputHandler {
	return &trivyignoreOutputHandler{w: w}
}

func (h *trivyignoreOutputHandler) HandleStatements(stmts []vex.Statement) error {
	for _, stmt := range stmts {
		stmtJ, err := json.Marshal(stmt)
		if err != nil {
			return err
		}
		ent := fmt.Sprintf(`# %s
%s

`, string(stmtJ), stmt.Vulnerability.ID)
		if _, err = h.w.Write([]byte(ent)); err != nil {
			return err
		}
	}
	return nil
}

func (h *trivyignoreOutputHandler) Close() error {
	return h.w.Close()
}

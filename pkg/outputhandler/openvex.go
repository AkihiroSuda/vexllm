package outputhandler

import (
	"io"

	"github.com/openvex/go-vex/pkg/vex"
)

type openvexOutputHandler struct {
	w      io.WriteCloser
	stmts  []vex.Statement
	closed bool
}

func NewOpenvexOutputHandler(w io.WriteCloser) OutputHandler {
	return &openvexOutputHandler{w: w}
}

func (h *openvexOutputHandler) HandleStatements(stmts []vex.Statement) error {
	h.stmts = append(h.stmts, stmts...)
	return nil
}

func (h *openvexOutputHandler) Close() error {
	if h.closed {
		return nil
	}
	doc := vex.New()
	doc.Author = "VexLLM"
	doc.AuthorRole = "AI"
	doc.Statements = h.stmts
	if _, err := doc.GenerateCanonicalID(); err != nil {
		return err
	}
	if err := doc.ToJSON(h.w); err != nil {
		return err
	}
	if err := h.w.Close(); err != nil {
		return err
	}
	h.closed = true
	return nil
}

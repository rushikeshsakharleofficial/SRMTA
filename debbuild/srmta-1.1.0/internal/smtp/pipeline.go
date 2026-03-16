// pipeline.go implements SMTP command pipelining support per RFC 2920.
// Pipelining allows multiple commands to be sent without waiting for
// individual responses, improving throughput for high-volume delivery.
package smtp

import (
	"bufio"
	"fmt"
	"strings"
)

// PipelinedDelivery sends MAIL+RCPT+DATA commands in a pipelined fashion.
// This is used when the remote server advertises PIPELINING in EHLO response.
type PipelinedDelivery struct {
	writer *bufio.Writer
	reader *bufio.Reader
}

// NewPipelinedDelivery creates a new pipelined delivery handler.
func NewPipelinedDelivery(reader *bufio.Reader, writer *bufio.Writer) *PipelinedDelivery {
	return &PipelinedDelivery{
		reader: reader,
		writer: writer,
	}
}

// SendPipelined sends MAIL FROM and multiple RCPT TO commands in a pipeline,
// then processes all responses together. Returns per-recipient results.
func (p *PipelinedDelivery) SendPipelined(from string, recipients []string) (map[string]PipelineResult, error) {
	// Pipeline group 1: MAIL FROM + all RCPT TO commands
	cmdCount := 1 + len(recipients) // MAIL FROM + RCPT TOs

	// Send MAIL FROM
	p.writer.WriteString(fmt.Sprintf("MAIL FROM:<%s>\r\n", from))

	// Send all RCPT TO
	for _, rcpt := range recipients {
		p.writer.WriteString(fmt.Sprintf("RCPT TO:<%s>\r\n", rcpt))
	}

	// Flush all pipelined commands
	if err := p.writer.Flush(); err != nil {
		return nil, fmt.Errorf("pipeline flush failed: %w", err)
	}

	// Read all responses
	responses := make([]PipelineResult, cmdCount)
	for i := 0; i < cmdCount; i++ {
		code, msg, err := p.readPipelineResponse()
		if err != nil {
			return nil, fmt.Errorf("pipeline response %d read failed: %w", i, err)
		}
		responses[i] = PipelineResult{Code: code, Message: msg}
	}

	// Map results: first response is MAIL FROM, rest are RCPT TO
	results := make(map[string]PipelineResult)

	// Check MAIL FROM response
	if responses[0].Code != 250 {
		// MAIL FROM failed, all recipients fail
		for _, rcpt := range recipients {
			results[rcpt] = PipelineResult{
				Code:    responses[0].Code,
				Message: "MAIL FROM rejected: " + responses[0].Message,
				Success: false,
			}
		}
		return results, nil
	}

	// Map RCPT TO responses
	for i, rcpt := range recipients {
		resp := responses[i+1]
		resp.Success = resp.Code == 250 || resp.Code == 251
		results[rcpt] = resp
	}

	return results, nil
}

// PipelineResult holds the result for a single pipelined command.
type PipelineResult struct {
	Code    int
	Message string
	Success bool
}

// readPipelineResponse reads a single SMTP response (potentially multi-line).
func (p *PipelinedDelivery) readPipelineResponse() (int, string, error) {
	var lines []string
	var code int

	for {
		line, err := p.reader.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		line = strings.TrimRight(line, "\r\n")

		if len(line) < 3 {
			return 0, "", fmt.Errorf("short response line: %q", line)
		}

		c := 0
		for i := 0; i < 3; i++ {
			c = c*10 + int(line[i]-'0')
		}
		code = c

		msg := ""
		if len(line) > 4 {
			msg = line[4:]
		}
		lines = append(lines, msg)

		if len(line) == 3 || line[3] == ' ' {
			break
		}
	}

	return code, strings.Join(lines, "\n"), nil
}

// SupportsExtension checks if a specific ESMTP extension was advertised.
func SupportsExtension(ehloResponse string, extension string) bool {
	lines := strings.Split(ehloResponse, "\n")
	extension = strings.ToUpper(extension)
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), extension) {
			return true
		}
	}
	return false
}

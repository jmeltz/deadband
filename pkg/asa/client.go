package asa

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/integration"
	"golang.org/x/crypto/ssh"
)

// Client manages an SSH session to a Cisco ASA.
type Client struct {
	cfg            integration.ASAConfig
	conn           *ssh.Client
	session        *ssh.Session
	stdin          io.Writer
	reader         *bufio.Reader
	hostname       string
	enablePassword string
}

// NewClient creates an ASA client from an integration config.
func NewClient(cfg integration.ASAConfig) *Client {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	return &Client{
		cfg:            cfg,
		enablePassword: cfg.EnablePassword,
	}
}

// TestConnection opens an SSH connection, reads the prompt, and closes.
func (c *Client) TestConnection(ctx context.Context) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	defer c.Close()
	return nil
}

// Connect establishes the SSH session with PTY allocation.
func (c *Client) Connect(ctx context.Context) error {
	var authMethods []ssh.AuthMethod

	if c.cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(c.cfg.Password))
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = c.cfg.Password
				}
				return answers, nil
			},
		))
	}

	config := &ssh.ClientConfig{
		User:            c.cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(c.cfg.Host, fmt.Sprintf("%d", c.cfg.Port))

	var err error
	c.conn, err = ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH dial failed: %w", err)
	}

	c.session, err = c.conn.NewSession()
	if err != nil {
		c.Close()
		return fmt.Errorf("SSH session failed: %w", err)
	}

	// Request PTY — xterm, 40 rows x 200 cols, 115200 baud
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	if err := c.session.RequestPty("xterm", 40, 200, modes); err != nil {
		c.Close()
		return fmt.Errorf("PTY request failed: %w", err)
	}

	c.stdin, err = c.session.StdinPipe()
	if err != nil {
		c.Close()
		return fmt.Errorf("stdin pipe failed: %w", err)
	}

	stdout, err := c.session.StdoutPipe()
	if err != nil {
		c.Close()
		return fmt.Errorf("stdout pipe failed: %w", err)
	}
	c.reader = bufio.NewReaderSize(stdout, 65536)

	if err := c.session.Shell(); err != nil {
		c.Close()
		return fmt.Errorf("shell start failed: %w", err)
	}

	// Read initial prompt
	output, err := c.readUntilPrompt(10 * time.Second)
	if err != nil {
		c.Close()
		return fmt.Errorf("initial prompt read failed: %w", err)
	}

	// Extract hostname from prompt
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasSuffix(line, ">") || strings.HasSuffix(line, "#") {
			c.hostname = strings.TrimRight(line, ">#")
			break
		}
	}

	// Enter enable mode if password provided
	if c.enablePassword != "" && !strings.HasSuffix(strings.TrimSpace(output), "#") {
		if _, err := fmt.Fprintf(c.stdin, "enable\n"); err != nil {
			c.Close()
			return fmt.Errorf("enable command failed: %w", err)
		}
		passOutput, err := c.readUntilPrompt(5 * time.Second)
		if err != nil {
			c.Close()
			return fmt.Errorf("enable prompt read failed: %w", err)
		}
		if strings.Contains(passOutput, "assword") {
			if _, err := fmt.Fprintf(c.stdin, "%s\n", c.enablePassword); err != nil {
				c.Close()
				return fmt.Errorf("enable password send failed: %w", err)
			}
			if _, err := c.readUntilPrompt(5 * time.Second); err != nil {
				c.Close()
				return fmt.Errorf("enable password response failed: %w", err)
			}
		}
	}

	// Disable paging
	c.Execute("terminal pager 0")

	return nil
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// readUntilPrompt reads output until a > or # prompt is detected.
// Handles <--- More ---> pagination by sending space.
func (c *Client) readUntilPrompt(timeout time.Duration) (string, error) {
	var buf strings.Builder
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		line, err := c.readLineWithTimeout(time.Until(deadline))
		if err != nil {
			if buf.Len() > 0 {
				return buf.String(), nil
			}
			return "", err
		}

		// Strip ANSI escapes
		line = ansiEscape.ReplaceAllString(line, "")

		// Handle pagination
		if strings.Contains(line, "<--- More --->") {
			fmt.Fprint(c.stdin, " ")
			continue
		}

		buf.WriteString(line)
		buf.WriteString("\n")

		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, ">") || strings.HasSuffix(trimmed, "#") {
			return buf.String(), nil
		}
	}

	return buf.String(), fmt.Errorf("prompt timeout after %v", timeout)
}

func (c *Client) readLineWithTimeout(timeout time.Duration) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := c.reader.ReadString('\n')
		ch <- result{strings.TrimRight(line, "\r\n"), err}
	}()

	select {
	case r := <-ch:
		return r.line, r.err
	case <-time.After(timeout):
		return "", fmt.Errorf("read timeout")
	}
}

// Execute runs a command and returns the output.
func (c *Client) Execute(cmd string) (string, error) {
	return c.executeRaw(cmd)
}

// executeRaw sends a command, reads the output, and strips the command echo and trailing prompt.
func (c *Client) executeRaw(cmd string) (string, error) {
	if _, err := fmt.Fprintf(c.stdin, "%s\n", cmd); err != nil {
		return "", fmt.Errorf("writing command: %w", err)
	}

	// Longer timeout for slow commands
	timeout := 15 * time.Second
	if strings.Contains(cmd, "access-list") || strings.Contains(cmd, "logging") {
		timeout = 45 * time.Second
	}

	output, err := c.readUntilPrompt(timeout)
	if err != nil {
		return output, err
	}

	// Strip command echo (first line) and trailing prompt (last line)
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		first := strings.TrimSpace(lines[0])
		if strings.Contains(first, cmd) || strings.TrimSpace(cmd) == first {
			lines = lines[1:]
		}
	}
	if len(lines) > 0 {
		last := strings.TrimSpace(lines[len(lines)-1])
		if strings.HasSuffix(last, ">") || strings.HasSuffix(last, "#") || last == "" {
			lines = lines[:len(lines)-1]
		}
	}

	return strings.Join(lines, "\n"), nil
}

// Close terminates the SSH session and connection.
func (c *Client) Close() {
	if c.session != nil {
		c.session.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

// Command interop drives the Go Soar client against a running server (the Rust one, in CI) and
// checks what comes back. It serves its own origin on loopback, so the server must be started
// with -allow-private -allow-ports any.
//
//	go run . -server 127.0.0.1:5353 -pubkey BASE64 -zone t.example.com
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/getlantern/soar"
)

func main() {
	server := flag.String("server", "127.0.0.1:5353", "server address, used as the client's only resolver")
	pubkey := flag.String("pubkey", "", "the server's base64 public key")
	zone := flag.String("zone", "t.example.com", "tunnel zone")
	run := flag.String("run", "", "run only checks whose names match this regexp")
	verbose := flag.Bool("v", false, "print the client's path stats after each check")
	flag.Parse()
	key, err := base64.StdEncoding.DecodeString(*pubkey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		fail("bad -pubkey")
	}
	origin := startOrigin()

	c, err := soar.NewClient(soar.Config{
		Zone:      *zone,
		ServerKey: ed25519.PublicKey(key),
		Resolvers: []string{*server},
		TCP:       "off",
	})
	if err != nil {
		fail("client: %v", err)
	}
	defer c.Close()

	checks := []struct {
		name string
		fn   func(*soar.Client, string) error
	}{
		{"fetch 1 byte", func(c *soar.Client, o string) error { return fetch(c, o, 1) }},
		{"fetch 100 KB", func(c *soar.Client, o string) error { return fetch(c, o, 100<<10) }},
		{"fetch 1 MB", func(c *soar.Client, o string) error { return fetch(c, o, 1<<20) }},
		{"upload 200 KB", upload},
		{"echo 200 KB", echo},
		{"8 concurrent fetches", concurrent},
		{"unreachable destination", unreachable},
		{"OPENED before data", opened},
	}
	filter, err := regexp.Compile(*run)
	if err != nil {
		fail("bad -run: %v", err)
	}
	failed := 0
	for _, ch := range checks {
		if !filter.MatchString(ch.name) {
			continue
		}
		start := time.Now()
		err := ch.fn(c, origin)
		status := "ok  "
		if err != nil {
			status, failed = "FAIL", failed+1
		}
		fmt.Printf("%s %-26s %6.2fs", status, ch.name, time.Since(start).Seconds())
		if err != nil {
			fmt.Printf("  %v", err)
		}
		fmt.Println()
		if *verbose {
			for _, p := range c.PathStats() {
				fmt.Printf("     path %s rtt=%v loss=%.2f window=%.1f answer_limit=%d name_len=%d successes=%d\n",
					p.Resolver, p.RTT.Round(time.Millisecond), p.Loss, p.Window, p.AnswerLimit, p.NameLen, p.Successes)
			}
		}
	}
	if failed > 0 {
		fail("%d of %d checks failed", failed, len(checks))
	}
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "interop: "+f+"\n", a...)
	os.Exit(1)
}

// startOrigin serves "N\n" → N pattern bytes, echoes when the request is "echo\n", and for
// "sink\n" reads to EOF and replies with the byte count.
func startOrigin() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("origin: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var line []byte
				b := make([]byte, 1)
				for {
					if _, err := c.Read(b); err != nil {
						return
					}
					if b[0] == '\n' {
						break
					}
					line = append(line, b[0])
				}
				if string(line) == "echo" {
					io.Copy(c, c)
					return
				}
				if string(line) == "sink" {
					n, _ := io.Copy(io.Discard, c)
					fmt.Fprintf(c, "%d", n)
					return
				}
				var n int
				fmt.Sscan(string(line), &n)
				c.Write(pattern(n))
			}()
		}
	}()
	return ln.Addr().String()
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

func fetch(c *soar.Client, origin string, n int) error {
	ctx, cancel := ctx()
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", origin)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := fmt.Fprintf(conn, "%d\n", n); err != nil {
		return err
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("after %d bytes: %w", len(got), err)
	}
	if !bytes.Equal(got, pattern(n)) {
		return fmt.Errorf("got %d bytes, want %d (or corrupted)", len(got), n)
	}
	return nil
}

func echo(c *soar.Client, origin string) error {
	ctx, cancel := ctx()
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", origin)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	want := pattern(200 << 10)
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(append([]byte("echo\n"), want...))
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		errc <- err
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("after %d bytes: %w", len(got), err)
	}
	if werr := <-errc; werr != nil {
		return werr
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("echoed %d bytes, want %d (or corrupted)", len(got), len(want))
	}
	return nil
}

func upload(c *soar.Client, origin string) error {
	ctx, cancel := ctx()
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", origin)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	n := 200 << 10
	if _, err := conn.Write(append([]byte("sink\n"), pattern(n)...)); err != nil {
		return err
	}
	conn.(interface{ CloseWrite() error }).CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if string(got) != fmt.Sprint(n) {
		return fmt.Errorf("origin got %q bytes, want %d", got, n)
	}
	return nil
}

func concurrent(c *soar.Client, origin string) error {
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = fetch(c, origin, 20<<10+i)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// unreachable: a refused destination comes back as a reset stream, not a hang.
func unreachable(c *soar.Client, _ string) error {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens here now
	ctx, cancel := ctx()
	defer cancel()
	_, err := c.NewRoundTripper(ctx, addr)
	if err == nil {
		return errors.New("connected to a closed port")
	}
	if ctx.Err() != nil {
		return fmt.Errorf("no answer before the deadline: %w", err)
	}
	return nil
}

// opened: NewRoundTripper returns only once the server reports the destination reachable.
func opened(c *soar.Client, origin string) error {
	ctx, cancel := ctx()
	defer cancel()
	_, err := c.NewRoundTripper(ctx, origin)
	return err
}

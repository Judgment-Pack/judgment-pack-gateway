package main

import (
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

// A connection of the PostgreSQL kind probes its peer after 5 s of quiet,
// every 5 s, three times: a server or a path that went away is known in
// about 20 s, not the system's default hours.
func TestAPostgresConnectionProbesItsPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	}()
	conn, err := pgDial(listener.Addr().String(), time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	var failed error
	raw.Control(func(fd uintptr) {
		for name, opt := range map[string][2]int{
			"keepalive": {syscall.SOL_SOCKET, syscall.SO_KEEPALIVE},
			"idle":      {syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE},
			"interval":  {syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL},
			"count":     {syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT},
		} {
			v, err := syscall.GetsockoptInt(int(fd), opt[0], opt[1])
			if err != nil {
				failed = err
			}
			got[name] = v
		}
	})
	if failed != nil {
		t.Fatal(failed)
	}
	if got["keepalive"] != 1 || got["idle"] != 5 || got["interval"] != 5 || got["count"] != 3 {
		t.Fatalf("the connection's keepalive: %v", got)
	}
}

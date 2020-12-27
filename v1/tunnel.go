package Tunnel

import (
	"io"
	"fmt"
	"time"
	"net"
	"context"
	"sync"
	"sync/atomic"
	"golang.org/x/crypto/ssh"
)

type KeepAliveConfig struct {
	// Interval is the amount of time in seconds to wait before the
	// Tunnel client will send a keep-alive message to ensure some minimum
	// traffic on the SSH connection.
	Interval uint
	// CountMax is the maximum number of consecutive failed responses to
	// keep-alive messages the client is willing to tolerate before considering
	// the SSH connection as dead.
	CountMax uint
}

type Tunnel struct {
	Auth     []ssh.AuthMethod
	HostKeys ssh.HostKeyCallback
	Mode     byte // '>' for forward, '<' for reverse
	User     string
	HostAddress string
	BindAddress string
	DialAddress string
	RetryInterval time.Duration
	KeepAlive     KeepAliveConfig
	//log Logger
}

func ( t Tunnel ) String() string {
	var left, right string
	mode := "<?>"
	switch t.Mode {
		case '>':
			left , mode , right = t.BindAddress , "->" , t.DialAddress
		case '<':
			left , mode , right = t.DialAddress , "<-" , t.BindAddress
	}
	return fmt.Sprintf( "%s@%s | %s %s %s" , t.User , t.HostAddress , left , mode , right )
}

func ( t Tunnel ) BindTunnel( ctx context.Context , wg *sync.WaitGroup ) {
	defer wg.Done()

	for {
		var once sync.Once // Only print errors once per session
		func() {
			// Connect to the server host via SSH.
			cl , err := ssh.Dial( "tcp" , t.HostAddress , &ssh.ClientConfig {
				User: t.User ,
				Auth: t.Auth ,
				HostKeyCallback: t.HostKeys ,
				Timeout: 5 * time.Second ,
			})
			if err != nil {
				once.Do( func() { fmt.Printf( "(%v) SSH dial error: %v\n" , t , err ) } )
				return
			}
			wg.Add( 1 )
			go t.KeepAliveMonitor( &once , wg , cl )
			defer cl.Close()

			// Attempt to bind to the inbound socket.
			var ln net.Listener
			switch t.Mode {
				case '>':
					ln , err = net.Listen( "tcp" , t.BindAddress )
				case '<':
					ln , err = cl.Listen( "tcp" , t.BindAddress )
			}
			if err != nil {
				once.Do( func() { fmt.Printf( "(%v) bind error: %v\n" , t , err ) } )
				return
			}

			// The socket is binded. Make sure we close it eventually.
			bindCtx , cancel := context.WithCancel ( ctx )
			defer cancel()
			go func() {
				cl.Wait()
				cancel()
			}()
			go func() {
				<-bindCtx.Done()
				once.Do( func() {} ) // Suppress future errors
				ln.Close()
			}()

			fmt.Printf( "(%v) binded tunnel\n" , t )
			defer fmt.Printf( "(%v) collapsed tunnel\n" , t )

			// Accept all incoming connections.
			for {
				cn1 , err := ln.Accept()
				if err != nil {
					once.Do( func() { fmt.Printf( "(%v) accept error: %v\n" , t , err ) } )
					return
				}
				wg.Add( 1 )
				go t.DialTunnel( bindCtx , wg , cl , cn1 )
			}
		}()

		select {
			case <-ctx.Done():
				return
			case <-time.After( t.RetryInterval ):
				fmt.Printf( "(%v) retrying...\n" , t )
		}
	}
}

func ( t Tunnel ) DialTunnel( ctx context.Context , wg *sync.WaitGroup , client *ssh.Client , cn1 net.Conn ) {
	defer wg.Done()

	// The inbound connection is established. Make sure we close it eventually.
	connCtx , cancel := context.WithCancel( ctx )
	defer cancel()
	go func() {
		<-connCtx.Done()
		cn1.Close()
	}()

	// Establish the outbound connection.
	var cn2 net.Conn
	var err error
	switch t.Mode {
		case '>':
			cn2 , err = client.Dial( "tcp" , t.DialAddress )
		case '<':
			cn2 , err = net.Dial( "tcp" , t.DialAddress )
	}
	if err != nil {
		fmt.Printf( "(%v) dial error: %v\n" , t , err )
		return
	}

	go func() {
		<-connCtx.Done()
		cn2.Close()
	}()

	fmt.Printf( "(%v) connection established\n" , t )
	defer fmt.Printf( "(%v) connection closed\n" , t )

	// Copy bytes from one connection to the other until one side closes.
	var once sync.Once
	var wg2 sync.WaitGroup
	wg2.Add( 2 )
	go func() {
		defer wg2.Done()
		defer cancel()
		if _ , err := io.Copy( cn1 , cn2 ); err != nil {
			once.Do( func() { fmt.Printf( "(%v) connection error: %v\n" , t , err ) } )
		}
		once.Do(func() {}) // Suppress future errors
	}()
	go func() {
		defer wg2.Done()
		defer cancel()
		if _ , err := io.Copy( cn2 , cn1 ); err != nil {
			once.Do( func() { fmt.Printf( "(%v) connection error: %v\n" , t , err ) } )
		}
		once.Do( func() {} ) // Suppress future errors
	}()
	wg2.Wait()
}

// KeepAliveMonitor periodically sends messages to invoke a response.
// If the server does not respond after some period of time,
// assume that the underlying net.Conn abruptly died.
func ( t Tunnel ) KeepAliveMonitor( once *sync.Once , wg *sync.WaitGroup , client *ssh.Client ) {
	defer wg.Done()
	if t.KeepAlive.Interval == 0 || t.KeepAlive.CountMax == 0 {
		return
	}

	// Detect when the SSH connection is closed.
	wait := make( chan error , 1 )
	wg.Add( 1 )
	go func() {
		defer wg.Done()
		wait <- client.Wait()
	}()

	// Repeatedly check if the remote server is still alive.
	var aliveCount int32
	ticker := time.NewTicker( time.Duration( t.KeepAlive.Interval ) * time.Second )
	defer ticker.Stop()
	for {
		select {
		case err := <-wait:
			if err != nil && err != io.EOF {
				once.Do( func() { fmt.Printf("(%v) SSH error: %v\n" , t , err ) } )
			}
			return
		case <-ticker.C:
			if n := atomic.AddInt32( &aliveCount , 1 ); n > int32( t.KeepAlive.CountMax ) {
				once.Do( func() { fmt.Printf( "(%v) SSH keep-alive termination\n" , t ) } )
				client.Close()
				return
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			_ , _ , err := client.SendRequest( "KeepAlive@openssh.com" , true , nil )
			if err == nil {
				atomic.StoreInt32( &aliveCount , 0 )
			}
		}()
	}
}
package main

import (
	"os"
	"os/signal"
	"fmt"
	"time"
	"net"
	"context"
	"path"
	"sync"
	"syscall"
	"golang.org/x/crypto/ssh"
	tunnel "sshtunnel/v1"
	robustly "github.com/VividCortex/robustly"
	//daemon "github.com/takama/daemon"
)

var SSH_KEY_FILE_DATA = []byte( `-----BEGIN OPENSSH PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END OPENSSH PRIVATE KEY-----` )
var SSH_KEY_FILE_PASSWORD = ""

func LoadConfig() ( tunns []tunnel.Tunnel , closer func() error ) {

	// 1.) Build Auth Agent and Config
	var auth []ssh.AuthMethod
	if SSH_KEY_FILE_PASSWORD != "" {
		auth = append( auth , ssh.Password( SSH_KEY_FILE_PASSWORD ) )
	}
	signer , err := ssh.ParsePrivateKey( SSH_KEY_FILE_DATA )
	if err != nil {
		fmt.Printf( "unable to parse private key: %v\n" , err )
	}
	auth = append( auth , ssh.PublicKeys( signer ) )

	// ssh $USER@$HOST -i /path/to/key.priv -L $BIND_ADDRESS:$BIND_PORT:$DIAL_ADDRESS:$DIAL_PORT
	// ssh $USER@$HOST -i /path/to/key.priv -R $BIND_ADDRESS:$BIND_PORT:$DIAL_ADDRESS:$DIAL_PORT

	// Example 1
	// Binds Redis from Tailscale Pihole to Localhost of Mini
	var tunn1 tunnel.Tunnel
	tunn1.Auth = auth
	tunn1.HostKeys = func( hostname string , remote net.Addr , key ssh.PublicKey ) error {
		return nil
	}
	tunn1.Mode = '>' // '>' for forward, '<' for reverse
	tunn1.User = "pi"
	tunn1.HostAddress = net.JoinHostPort( "111.222.333.444" , "22" )
	tunn1.BindAddress = "localhost:6379"
	tunn1.DialAddress = "localhost:6379"
	tunn1.RetryInterval = 30 * time.Second
	//tunn1.keepAlive = *KeepAliveConfig
	tunns = append( tunns , tunn1 )

	// Example 2
	// Binds Temporary Python Server from Mini to Localhost of Tailscale Pihole
	var tunn2 tunnel.Tunnel
	tunn2.Auth = auth
	tunn2.HostKeys = func( hostname string , remote net.Addr , key ssh.PublicKey ) error {
		return nil
	}
	tunn2.Mode = '<' // '>' for forward, '<' for reverse
	tunn2.User = "pi"
	tunn2.HostAddress = net.JoinHostPort( "111.222.333.444" , "22" )
	tunn2.BindAddress = "localhost:9559"
	tunn2.DialAddress = "localhost:9559"
	tunn2.RetryInterval = 30 * time.Second
	//tunn1.keepAlive = *KeepAliveConfig

	tunns = append( tunns , tunn2 )
	return tunns , closer
}


func Run() {
	tunns , closer := LoadConfig()
	defer closer()

	// Setup signal handler to initiate shutdown.
	ctx , cancel := context.WithCancel( context.Background() )
	go func() {
		sigc := make( chan os.Signal , 1 )
		signal.Notify( sigc , syscall.SIGINT , syscall.SIGTERM )
		fmt.Printf( "received %v - initiating shutdown\n" , <-sigc )
		cancel()
	}()

	// Start a bridge for each tunnel.Tunnel.
	var wg sync.WaitGroup
	fmt.Printf( "%s starting\n" , path.Base( os.Args[ 0 ] ) )
	defer fmt.Printf( "%s shutdown\n" , path.Base( os.Args[ 0 ] ) )
	for _ , t := range tunns {
		wg.Add( 1 )
		go t.BindTunnel( ctx , &wg )
	}
	wg.Wait()
}

func RobustlyRun() {
	robustly.Run( Run , &robustly.RunOptions{
		RateLimit:  1.0,
		Timeout:    time.Second ,
		PrintStack: false ,
		RetryDelay: 0 * time.Nanosecond ,
	})
}

func main() {
	fmt.Println( "Starting Tunnels" )
	RobustlyRun()
}
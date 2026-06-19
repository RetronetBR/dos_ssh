package main

import (
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

var FrameBufferUpdate chan []byte
var FrameBufferSubscribers map[string]chan []byte

// Start listening for SSH connections
func StartSSH() {
	PEM_KEY := LoadOrCreateHostKey("./id_rsa")
	private, err := ssh.ParsePrivateKey(PEM_KEY)
	if err != nil {
		log.Fatal("Key failed to parse.")
	}
	log.Println("SSH host key ready")

	SSHConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	SSHConfig.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatalln("Could not start TCP listening on 0.0.0.0:2222")
	}
	log.Println("Waiting for TCP conns on 0.0.0.0:2222")

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("WARNING - Failed to Accept TCP conn. RSN: %s / %s", err.Error(), err)
			continue
		}
		log.Printf("Accepted TCP conn from %s", nConn.RemoteAddr().String())
		go HandleIncomingSSHConn(nConn, SSHConfig)
	}
}

// Wait 10 seconds before closing the connection (To stop dead connections)
func TimeoutConnection(Done chan bool, nConn net.Conn) {
	select {
	case <-Done:
		return
	case <-time.After(time.Second * 10):
		nConn.Close()
	}
}

func HandleIncomingSSHConn(nConn net.Conn, config *ssh.ServerConfig) {
	log.Printf("Starting SSH handshake with %s", nConn.RemoteAddr().String())
	DoneCh := make(chan bool)
	go TimeoutConnection(DoneCh, nConn)
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("WARNING - SSH handshake failed with %s: %v", nConn.RemoteAddr().String(), err)
		_ = nConn.Close()
		return
	}
	DoneCh <- true
	log.Printf("SSH handshake complete with %s", nConn.RemoteAddr().String())
	// Right now that we are out of annoying people land.

	defer nConn.Close()
	go HandleSSHrequests(reqs)

	for newChannel := range chans {
		log.Printf("Incoming SSH channel %s from %s", newChannel.ChannelType(), nConn.RemoteAddr().String())
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			log.Printf("WARNING - Rejecting %s Because they asked for a chan type %s that I don't have", nConn.RemoteAddr().String(), newChannel.ChannelType())
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("WARNING - Was unable to Accept channel with %s", nConn.RemoteAddr().String())
			return
		}
		log.Printf("Accepted SSH session channel from %s", nConn.RemoteAddr().String())
		go HandleSSHrequests(requests)
		go ServeDOSTerm(channel)
	}

}

func HandleSSHrequests(in <-chan *ssh.Request) {
	for req := range in {
		log.Printf("SSH request received: type=%s wantReply=%t", req.Type, req.WantReply)
		if req.WantReply {
			// Ensure that the other end does not panic that we don't offer terminals
			if req.Type == "shell" || req.Type == "pty-req" || req.Type == "env" {
				log.Printf("SSH request accepted: type=%s", req.Type)
				req.Reply(true, nil)
			} else {
				log.Printf("SSH request rejected: type=%s", req.Type)
				req.Reply(false, nil)
			}
		}
	}
}

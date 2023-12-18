/**
 * Shogun - SSH jumphost manager
 *
 * ===
 *
 * Nomenclature:
 *
 *  _manager_:
 *      The jumphost SSH server which allows _clients_ to connect to _servers_.
 *      Access privileges are managed by the admininistrator (TODO: how?).
 *
 *  _server_:
 *        An SSH client that provides access to its TTY to _clients_.
 *
 *  _client_:
 *        An SSH client that gains access to TTY of _servers_.
 *
 *  _server-identifier_:
 *        Fingerprint of the _server_.
 *        Can be used for both setting _access-permissions_ and starting
 *        connections.
 *
 *  _server-tag_:
 *        Human-readable string that points to a _server-identifier_.
 *        Can be used for both setting _access-permissions_ and starting
 *        connections.
 *
 *  _server-group_:
 *        Human-readable string that refers to a set of _server-identifiers_.
 *        Can be used for setting _access-permissions_.
 *
 *  _client-identifier_:
 *        Fingerprint of the _client_.
 *        Can be used for both setting _access-permissions_ and starting
 *        connections.
 *
 *  _client-tag_:
 *        Human-readable string that points to a _client-identifier_.
 *        Can be used for setting _access-permissions_.
 *
 *  _client-group_:
 *        Human-readable string that refers to a set of _client-identifiers_.
 *        Can be used for setting _access-permissions_.
 *
 *  _access-permissions_:
 *        A set of tuples of (_C_, _S_), such that:
 *        1) _C_ is one of:
 *          - _client-identifier_
 *          - _client-tag_
 *          - _client-group_
 *        2) _S_ is one of:
 *          - _server-identifier_
 *          - _server-tag_
 *          - _server-group_
 *
 * ===
 *
 * Functionality:
 *
 *  _manager_
 *
 * Starts an SSH listener on port 2200.
 *
 * When an unknown _server_ connects, it records its fingerprint as a new entry
 * with no configured permissions. It is up to administrator to allow _clients_
 * to access the new _server_.
 *
 * Each _server_ has an _identifier_ (fingerprint).
 * Each _server_ has zero or more _tags_.
 * Each _server_ can belong to zero or more groups.
 *
 * A _client_ can be given permission to access a _server_ if, and only if, the
 * _access-permissions_ set contains a pair (_C_, _S_) such that _C_ refers to
 * the _client_ and _S_ refers to the _server_
 *
 * ===
 *
 * Step 1:
 *  - Create a working SSH client / server implementation that provides a TTY /
 *    byte stream
 *
 * Step 2:
 *  - ... (Create a reverse server using the byte stream)
 *
 * Step 3:
 *  - ... (Implement...??)
 */
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func main() {
	CreateSshKeyPair("id_rsa.pub", "id_rsa")
}

type AccessPermission struct {
}

func RunSshServerAndClient() {
	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	authorizedKeysBytes, err := os.ReadFile("authorized_keys")
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		/*
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				// Should use constant-time compare (or better, salt+hash) in
				// a production setting.
				if c.User() == "testuser" && string(pass) == "tiger" {
					return nil, nil
				}
				return nil, fmt.Errorf("password rejected for %q", c.User())
			},
		*/

		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	privateBytes, err := os.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection: ", err)
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}
	log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

	var wg sync.WaitGroup
	defer wg.Wait()

	// The incoming Request channel must be serviced.
	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Fatalf("Could not accept channel: %v", err)
		}

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "shell" request.
		wg.Add(1)
		go func(in <-chan *ssh.Request) {
			for req := range in {
				req.Reply(req.Type == "shell", nil)
			}
			wg.Done()
		}(requests)

		term := term.NewTerminal(channel, "> ")

		wg.Add(1)
		go func() {
			defer func() {
				channel.Close()
				wg.Done()
			}()
			for {
				line, err := term.ReadLine()
				if err != nil {
					break
				}
				fmt.Println(line)
			}
		}()
	}
}

// Make a pair of public and private keys for SSH access.
// Public key is encoded in the format for inclusion in an OpenSSH
// authorized_keys file.
// Private Key generated is PEM encoded.
func CreateSshKeyPair(pubKeyPath, privateKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("rsa generate key: %w", err)
	}

	privateKeyFile, err := os.OpenFile(
		privateKeyPath,
		os.O_CREATE|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return fmt.Errorf("open file '%s': %w", privateKeyPath, err)
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("pem encode to '%s': %w", privateKeyPath, err)
	}

	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("rsa to ssh public key: %w", err)
	}
	err = os.WriteFile(
		pubKeyPath,
		ssh.MarshalAuthorizedKey(pub),
		0644,
	)
	if err != nil {
		return fmt.Errorf("ssh public key write to '%s': %w", pubKeyPath, err)
	}
	return nil
}

/**
 * This function (attempts to) atomically writes data to a file specified by
 * the filename. It will probably work on Linux.
 */
func atomicWrite(filename string, data []byte) error {
	tempFilename := filename + ".temp"
	if err := os.WriteFile(tempFilename, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tempFilename, filename); err != nil {
		return err
	}
	return nil
}

package gerritssh

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// New creates, and returns a new GerritESListener object. Its only argument
// is a channel that the worker can add itself to whenever it is done its
// work.
func New(url string, username string, sshKeyPath string) GerritSSH {
	// Create, and return the worker.
	worker := GerritSSH{
		StopChan:   make(chan bool),
		ResultChan: make(chan StreamEvent),
		Username:   username,
		SSHKeyPath: sshKeyPath,
		URL:        url,
		Debug:      true,
	}

	worker.Debug = false

	return worker
}

// GerritSSH agent
type GerritSSH struct {
	ID         int
	Username   string
	SSHKeyPath string
	URL        string
	StopChan   chan bool
	ResultChan chan StreamEvent
	Debug      bool
}

// StartStreamEvents starts stream event routine
func (g *GerritSSH) StartStreamEvents() error {
	conn, session, err := g.sshSession()
	if err != nil {
		return err
	}
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return err
	}
	sessionScanner := bufio.NewScanner(stdoutPipe)

	errChan := make(chan error)
	go func() {
		if g.Debug {
			fmt.Println("Starting stream-events")
		}
		err := session.Run("gerrit stream-events")
		if err != nil {
			if g.Debug {
				fmt.Println("Gerrit-SSH: stream-events failed: " + err.Error())
			}
			stderrContent, err1 := ioutil.ReadAll(stderrPipe)
			if err1 == nil {
				if g.Debug {
					fmt.Println("Gerrit-SSH: failed to get stderr of stream-events command")
				}
				stderrContent = []byte("")
			}
			session.Close()
			conn.Close()
			errChan <- errors.Wrap(err, "Gerrit SSH: stream-events failed: "+string(stderrContent))
		}
		if g.Debug {
			fmt.Println("Gerrit-SSH: stream-events exited")
		}
		errChan <- errors.New("Gerrit SSH: stream-events exited")
	}()
	if g.Debug {
		fmt.Println("Started processing stream events")
	}
	go func() {
		defer conn.Close()
		defer session.Close()

		event := StreamEvent{}
		for sessionScanner.Scan() {
			eventTxt := sessionScanner.Text()
			err := json.Unmarshal([]byte(eventTxt), &event)
			if err == nil {
				if g.Debug {
					log.Printf("Gerrit SSH: recived event: %v", event.Type)
				}
				g.ResultChan <- event
			} else {
				if g.Debug {
					te := err.(*json.UnmarshalTypeError)
					log.Printf("Gerrit SSH: could not parse event at offset %d: %s:\n %s", te.Offset, err.Error(), ":\n", eventTxt)
				}
			}
			select {
			case err := <-errChan:
				log.Printf(err.Error())
				return
			case <-g.StopChan:
				if g.Debug {
					log.Printf("Gerrit SSH: Stop stream events")
				}
				return
			default:
			}
		}
	}()
	return nil
}

// StopStreamEvents stop stream event routine
func (g *GerritSSH) StopStreamEvents() {
	go func() {
		g.StopChan <- true
	}()
}

// Send command over SSH to gerrit instance
func (g *GerritSSH) Send(command string) (string, error) {
	return g.sshCommand(command, nil)
}

func (g *GerritSSH) sshSession() (*ssh.Client, *ssh.Session, error) {
	// Read ssh key
	if g.Debug {
		fmt.Println("Reading private key")
	}
	pemBytes, err := ioutil.ReadFile(g.SSHKeyPath)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}
	if g.Debug {
		fmt.Println("Parsing private key")
	}
	// Parse ssh key
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		log.Fatalf("Gerrit SSH: parse key failed:%v", err)
		return nil, nil, err
	}
	// Create config
	config := &ssh.ClientConfig{
		User: g.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if g.Debug {
		fmt.Println("Dialing " + g.URL)
	}
	// Dial TCP
	conn, err := ssh.Dial("tcp", g.URL, config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Gerrit SSH: dial failed")
	}
	if g.Debug {
		fmt.Println("Connected, establishing session")
	}
	// Start new session
	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return nil, nil, errors.Wrap(err, "Gerrit SSH: session create failed")
	}
	if g.Debug {
		fmt.Println("Session established")
	}

	// defer session.Close()
	return conn, session, nil
}

func (g *GerritSSH) sshCommand(command string, buffer *bytes.Buffer) (string, error) {
	conn, session, err := g.sshSession()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if buffer != nil {
		session.Stdout = buffer
	} else {
		buffer = &bytes.Buffer{}
		session.Stdout = buffer
	}

	err = session.Run("gerrit " + command)
	if err != nil {
		log.Fatalf("Gerrit SSH: run failed:%v", err)
		return "", errors.Wrap(err, "Gerrit SSH: run failed")
	}

	return buffer.String(), nil
}

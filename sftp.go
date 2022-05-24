package gosftp

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/pkg/sftp"
)

// ClientConfig is the configuration for the sftp client
type ClientConfig struct {
	User     string // User name
	Password string // Password

	Host string // Hostname or IP address
	Port int    // Default SFTP port, 22 if not provided

	IgnoreHostKeyValidation bool // If false, host key validation is enabled. It should be false for production use.
}

// Client is the sftp client
type Client struct {
	client *sftp.Client
	con    *ssh.Client
}

type File struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
}

func NewClient(config ClientConfig) (c *Client, err error) {
	user := config.User
	pass := config.Password
	host := config.Host

	// Default SFTP port
	port := config.Port
	if config.Port == 0 {
		port = 22
	}

	hostKey, _ := getHostKey(host)

	var auths []ssh.AuthMethod

	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
	}

	// Use password authentication if provided
	if pass != "" {
		auths = append(auths, ssh.Password(pass))
	}

	var hostKeyCallback ssh.HostKeyCallback
	if config.IgnoreHostKeyValidation {
		hostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec
	} else {
		hostKeyCallback = ssh.FixedHostKey(hostKey)
	}

	// Initialize client configuration
	configClient := ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: hostKeyCallback,
		HostKeyAlgorithms: []string{
			ssh.CertAlgoRSAv01,
			ssh.CertAlgoDSAv01,
			ssh.CertAlgoECDSA256v01,
			ssh.CertAlgoECDSA384v01,
			ssh.CertAlgoECDSA521v01,
			ssh.CertAlgoED25519v01,

			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoDSA,

			ssh.KeyAlgoED25519,
		},
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	// Connect to server
	conn, err := ssh.Dial("tcp", addr, &configClient)
	if err != nil {
		return nil, fmt.Errorf("failed to connecto to [%s]: %w", addr, err)
	}

	// Create new SFTP client
	sc, err := sftp.NewClient(conn)
	if err != nil {
		return nil, fmt.Errorf("unable to start sftp subsystem: %v", err)
	}

	return &Client{
		client: sc,
		con:    conn,
	}, nil
}

// ListFiles List files in the given path
func (c Client) ListFiles(remoteDir string) ([]File, error) {
	files, err := c.client.ReadDir(remoteDir)
	if err != nil {
		return nil, fmt.Errorf("unable to list remote dir: %w", err)
	}

	remoteFiles := make([]File, 0, len(files))

	for _, f := range files {
		name := f.Name()

		remoteFiles = append(remoteFiles, File{
			Name:    name,
			ModTime: f.ModTime(),
			Size:    f.Size(),
			IsDir:   f.IsDir(),
		})
	}

	return remoteFiles, nil
}

// UploadFile Upload file to sftp server
func (c *Client) UploadFile(localFile, remoteFile string) (err error) {
	srcFile, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("unable to open local file: %w", err)
	}
	defer srcFile.Close()

	// Make remote directories recursion
	parent := filepath.Dir(remoteFile)
	path := string(filepath.Separator)
	dirs := strings.Split(parent, path)

	for _, dir := range dirs {
		path = filepath.Join(path, dir)

		err = c.client.Mkdir(path)
		if err != nil {
			return fmt.Errorf("unable to create remote directory: %w", err)
		}
	}

	// Note: SFTP To Go doesn't support O_RDWR mode
	dstFile, err := c.client.OpenFile(remoteFile, (os.O_WRONLY | os.O_CREATE | os.O_TRUNC))
	if err != nil {
		return fmt.Errorf("unable to open remote file: %w", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("unable to upload local file: %w", err)
	}

	return nil
}

// Download file from sftp server
func (c *Client) DownloadFile(remoteFile string, localFile string) (err error) {
	// Note: SFTP To Go doesn't support O_RDWR mode
	srcFile, err := c.client.OpenFile(remoteFile, (os.O_RDONLY))
	if err != nil {
		return fmt.Errorf("unable to open remote file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("unable to open local file: %w", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("unable to download remote file: %w", err)
	}

	return nil
}

// ReadFile read file from sftp server
func (c *Client) ReadFile(remoteFile string) (io.Reader, error) {
	// Note: SFTP To Go doesn't support O_RDWR mode
	srcFile, err := c.client.OpenFile(remoteFile, (os.O_RDONLY))
	if err != nil {
		return nil, fmt.Errorf("unable to open remote file: %w", err)
	}

	return srcFile, nil
}

// Close close the sftp client and connection
func (c *Client) Close() {
	c.client.Close()
	c.con.Close()
}

// Get host key from local known hosts
func getHostKey(host string) (ssh.PublicKey, error) {
	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		return nil, fmt.Errorf("unable to read known_hosts file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}

		if strings.Contains(fields[0], host) {
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, fmt.Errorf("error parsing %q: %w", fields[2], err)
			}

			break
		}
	}

	if hostKey == nil {
		return nil, fmt.Errorf("no hostkey found for %s", host)
	}

	return hostKey, nil
}

func signerFromPem(pemBytes []byte, password []byte) (ssh.Signer, error) {

	// read pem block
	err := errors.New("Pem decode failed, no key found")
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, err
	}

	// handle encrypted key
	if x509.IsEncryptedPEMBlock(pemBlock) {
		// decrypt PEM
		pemBlock.Bytes, err = x509.DecryptPEMBlock(pemBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("Decrypting PEM block failed %v", err)
		}

		// get RSA, EC or DSA key
		key, err := parsePemBlock(pemBlock)
		if err != nil {
			return nil, fmt.Errorf("Parsing Block Error %v", err)
		}

		// generate signer instance from key
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, fmt.Errorf("Creating signer from encrypted key failed %v", err)
		}

		return signer, nil
	} else {
		// generate signer instance from plain key
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing plain private key failed %v", err)
		}

		return signer, nil
	}
}

func parsePemBlock(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing PKCS private key failed %v", err)
		} else {
			return key, nil
		}
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing EC private key failed %v", err)
		} else {
			return key, nil
		}
	case "DSA PRIVATE KEY":
		key, err := ssh.ParseDSAPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing DSA private key failed %v", err)
		} else {
			return key, nil
		}
	default:
		return nil, fmt.Errorf("Parsing private key failed, unsupported key type %q", block.Type)
	}
}

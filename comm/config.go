package comm

type Config struct {
	// node id in multisig
	ID int

	// name given to the node
	Name string

	// IP address, in the form of host:port, given the TLS server run by the node
	Address string

	// IP address, in the form of host:port, given the RPC server run by the node
	RPCAddress string

	// paths to the TLS certificate and key used to run a TLS server
	Cert string
	Key  string

	// path to the CA certificate used to generate the above certificates
	CACert string

	Peers []PeerConfig

	Clients []ClientConfig
}

type PeerConfig struct {
	// peer id in multisig
	ID int

	// name given to the peer
	Name string

	// IP address, in the form of host:port, given the TLS server run by the peer
	Address string // host:port

	// IP address, in the form of host:port, given the RPC server run by the peer
	RPCAddress string

	// path to the CA certificate used to authenticate the peer during TLS handshake
	CACert string
}

type ClientConfig struct {
	// client id in multisig
	UserID int

	// name given to the client
	Name string

	// path to the CA certificate used to authenticate the client during TLS handshake
	CACert string
}

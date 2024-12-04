package comm

type Config struct {
	// node id in multisig
	ID int

	// name given to the node
	Name string

	// IP address, in the form of host:port, given the TLS server run by the node
	Address string

	// IP address, in the form of host:port, given the RPC server run by the node
	RpcAddress string

	// paths to the TLS certificate and key used to run a TLS server
	Cert string
	Key  string

	// path to the CA certificate used to generate the above certificates
	CaCert string

	Peers []PeerConfig

	// path to the CA certificate used to authenticate the client during TLS handshake
	ClientsCaCert []string
}

type PeerConfig struct {
	// peer id in multisig
	ID int

	// name given to the peer
	Name string

	// IP address, in the form of host:port, given the TLS server run by the peer
	Address string // host:port

	// IP address, in the form of host:port, given the RPC server run by the peer
	RpcAddress string

	// path to the CA certificate used to authenticate the peer during TLS handshake
	CaCert string
}

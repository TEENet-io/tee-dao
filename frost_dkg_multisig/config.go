package frost_dkg_multisig

type NodeConfig struct {
	// The name of the node
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
	// IP address of the remote coordinator server, in the form of host:port
	CoordinatorAddress string
	// path to the CA certificate used to authenticate the remote coordinator server during TLS handshake
	CoordinatorCACert string
	// list of the paths to the Clients CA certificate files
	ClientsCACert []string
}

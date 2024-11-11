package comm

import (
	"fmt"
	"path/filepath"
)

func prepareTest(dir string, ports []string) []*Config {
	names := []string{}
	addresses := []string{}
	certFiles := []string{}
	keyFiles := []string{}
	CACertFiles := []string{}
	for i, port := range ports {
		addresses = append(addresses, "localhost:"+port)
		names = append(names, "node"+fmt.Sprintf("%d", i))
		certFiles = append(certFiles, filepath.Join(dir, "node"+fmt.Sprintf("%d", i)+"-server.crt"))
		keyFiles = append(keyFiles, filepath.Join(dir, "node"+fmt.Sprintf("%d", i)+"-server.key"))
		CACertFiles = append(CACertFiles, filepath.Join(dir, "node"+fmt.Sprintf("%d", i)+"-ca.crt"))
	}

	cfgs := []*Config{}
	for i := 0; i < len(ports); i++ {
		cfg := &Config{
			Name:    names[i],
			Address: addresses[i],
			Cert:    certFiles[i],
			Key:     keyFiles[i],
			CACert:  CACertFiles[i],
		}
		cfg.Peers = []PeerConfig{}
		for j := 0; j < len(ports); j++ {
			if i == j {
				continue
			}
			cfg.Peers = append(cfg.Peers, PeerConfig{
				Name:    names[j],
				Address: addresses[j],
				CACert:  CACertFiles[j],
			})
		}
		cfgs = append(cfgs, cfg)
	}

	return cfgs
}

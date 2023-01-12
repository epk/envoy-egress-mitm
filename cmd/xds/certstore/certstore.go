package certstore

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/epk/envoy-egress-mitm/types"
	"github.com/fsnotify/fsnotify"
)

func NewConfigStore(path string) *CertStore {
	store := &CertStore{
		watchPath: path,
	}

	return store
}

type CertStore struct {
	rw sync.RWMutex

	watchPath string

	watcher  *fsnotify.Watcher
	updateCh chan struct{}

	certificates map[string]*types.Certificate
}

func (c *CertStore) StartWatcher() (<-chan struct{}, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	if err := watcher.Add(c.watchPath); err != nil {
		return nil, err
	}

	c.watcher = watcher

	ch := make(chan struct{}, 10)
	c.updateCh = ch

	go func() {
		defer close(c.updateCh)
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				switch event.Op {
				case fsnotify.Create, fsnotify.Write:
					cert, err := c.readCerficateFromDisk(event.Name)
					if err != nil {
						log.Println("error reading certificate from disk:", err)
						continue
					}

					c.updateCertificate(event.Name, cert)
					c.updateCh <- struct{}{}
				case fsnotify.Remove:
					c.deleteCertificate(event.Name)
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error watching config file:", err)
			}
		}
	}()

	return ch, nil
}

func (c *CertStore) List() []*types.Certificate {
	c.rw.RLock()
	defer c.rw.RUnlock()

	var certs []*types.Certificate
	for _, cert := range c.certificates {
		certs = append(certs, cert)
	}

	return certs
}

func (c *CertStore) Close() error {
	if c.watcher != nil {
		defer func() {
			c.watcher = nil
		}()
		return c.watcher.Close()
	}
	return nil
}

func (c *CertStore) deleteCertificate(path string) {
	c.rw.Lock()
	defer c.rw.Unlock()

	delete(c.certificates, path)
}

func (c *CertStore) readCerficateFromDisk(path string) (*types.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cert := &types.Certificate{}

	if err := json.Unmarshal(data, cert); err != nil {
		return nil, err
	}

	return cert, nil
}

func (c *CertStore) updateCertificate(path string, cert *types.Certificate) {
	c.rw.Lock()
	defer c.rw.Unlock()

	if c.certificates == nil {
		c.certificates = make(map[string]*types.Certificate)
	}

	c.certificates[path] = cert
}

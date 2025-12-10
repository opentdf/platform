package sdk

import (
	"bytes"
	"sync"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
)

// ============================================================================================================
// NanoTDF Collection Header Store
// ============================================================================================================

const (
	kDefaultExpirationTime   = 5 * time.Minute
	kDefaultCleaningInterval = 10 * time.Minute
)

type collectionStore struct {
	cache          sync.Map
	expireDuration time.Duration
	closeChan      chan struct{}
}

type collectionStoreEntry struct {
	key             []byte
	encryptedHeader []byte
	expire          time.Time
}

func newCollectionStore(expireDuration, cleaningInterval time.Duration) *collectionStore {
	store := &collectionStore{expireDuration: expireDuration, cache: sync.Map{}, closeChan: make(chan struct{})}
	store.startJanitor(cleaningInterval)
	return store
}

func (c *collectionStore) startJanitor(cleaningInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(cleaningInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				c.cache.Range(func(key, value any) bool {
					entry, _ := value.(*collectionStoreEntry)
					if now.Compare(entry.expire) >= 0 {
						c.cache.Delete(key)
					}
					return true
				})
			case <-c.closeChan:
				return
			}
		}
	}()
}

func (c *collectionStore) Store(header, key []byte) {
	hash := ocrypto.SHA256AsHex(header)
	expire := time.Now().Add(c.expireDuration)
	c.cache.Store(string(hash), &collectionStoreEntry{key: key, encryptedHeader: header, expire: expire})
}

func (c *collectionStore) Get(header []byte) ([]byte, bool) {
	hash := ocrypto.SHA256AsHex(header)
	itemIntf, ok := c.cache.Load(string(hash))
	if !ok {
		return nil, false
	}
	item, _ := itemIntf.(*collectionStoreEntry)
	// check for hash collision
	if bytes.Equal(item.encryptedHeader, header) {
		return item.key, true
	}
	return nil, false
}

func (c *collectionStore) close() {
	c.closeChan <- struct{}{}
}

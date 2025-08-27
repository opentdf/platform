package segment

import (
	"container/list"
	"sync"
)

// SegmentCache provides thread-safe LRU caching for segment information
type Cache struct {
	mu        sync.RWMutex
	capacity  int
	items     map[int]*list.Element
	evictList *list.List
}

// cacheItem represents a cached segment
type cacheItem struct {
	key   int
	value *Info
}

// NewSegmentCache creates a new LRU cache for segments
func NewSegmentCache(capacity int) *Cache {
	return &Cache{
		capacity:  capacity,
		items:     make(map[int]*list.Element),
		evictList: list.New(),
	}
}

// Get retrieves a segment from cache
func (sc *Cache) Get(key int) (*Info, bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if elem, exists := sc.items[key]; exists {
		// Move to front (most recently used)
		sc.evictList.MoveToFront(elem)
		if item, ok := elem.Value.(*cacheItem); ok {
			return item.value, true
		}
	}

	return nil, false
}

// Put adds a segment to cache
func (sc *Cache) Put(key int, value *Info) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Check if item already exists
	if elem, exists := sc.items[key]; exists {
		// Update existing item and move to front
		if item, ok := elem.Value.(*cacheItem); ok {
			item.value = value
			sc.evictList.MoveToFront(elem)
			return
		}
	}

	// Add new item
	item := &cacheItem{key: key, value: value}
	elem := sc.evictList.PushFront(item)
	sc.items[key] = elem

	// Check if we need to evict
	if len(sc.items) > sc.capacity {
		sc.evictOldest()
	}
}

// Size returns the current number of items in cache
func (sc *Cache) Size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.items)
}

// Clear removes all items from cache
func (sc *Cache) Clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.items = make(map[int]*list.Element)
	sc.evictList.Init()
}

// Keys returns all keys in cache (for testing)
func (sc *Cache) Keys() []int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	keys := make([]int, 0, len(sc.items))
	for k := range sc.items {
		keys = append(keys, k)
	}
	return keys
}

// evictOldest removes the least recently used item
// Must be called with lock held
func (sc *Cache) evictOldest() {
	if sc.evictList.Len() == 0 {
		return
	}

	elem := sc.evictList.Back()
	if elem != nil {
		sc.evictList.Remove(elem)
		if item, ok := elem.Value.(*cacheItem); ok {
			delete(sc.items, item.key)
		}
	}
}

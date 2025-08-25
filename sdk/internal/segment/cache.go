package segment

import (
	"container/list"
	"sync"
)

// SegmentCache provides thread-safe LRU caching for segment information
type SegmentCache struct {
	mu        sync.RWMutex
	capacity  int
	items     map[int]*list.Element
	evictList *list.List
}

// cacheItem represents a cached segment
type cacheItem struct {
	key   int
	value *SegmentInfo
}

// NewSegmentCache creates a new LRU cache for segments
func NewSegmentCache(capacity int) *SegmentCache {
	return &SegmentCache{
		capacity:  capacity,
		items:     make(map[int]*list.Element),
		evictList: list.New(),
	}
}

// Get retrieves a segment from cache
func (sc *SegmentCache) Get(key int) (*SegmentInfo, bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if elem, exists := sc.items[key]; exists {
		// Move to front (most recently used)
		sc.evictList.MoveToFront(elem)
		return elem.Value.(*cacheItem).value, true
	}

	return nil, false
}

// Put adds a segment to cache
func (sc *SegmentCache) Put(key int, value *SegmentInfo) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Check if item already exists
	if elem, exists := sc.items[key]; exists {
		// Update existing item and move to front
		elem.Value.(*cacheItem).value = value
		sc.evictList.MoveToFront(elem)
		return
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
func (sc *SegmentCache) Size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.items)
}

// Clear removes all items from cache
func (sc *SegmentCache) Clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.items = make(map[int]*list.Element)
	sc.evictList.Init()
}

// Keys returns all keys in cache (for testing)
func (sc *SegmentCache) Keys() []int {
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
func (sc *SegmentCache) evictOldest() {
	if sc.evictList.Len() == 0 {
		return
	}

	elem := sc.evictList.Back()
	if elem != nil {
		sc.evictList.Remove(elem)
		delete(sc.items, elem.Value.(*cacheItem).key)
	}
}

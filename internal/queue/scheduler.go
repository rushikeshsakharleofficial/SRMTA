// scheduler.go implements priority-based delivery scheduling with domain bucketing
// and per-domain rate governance for the SRMTA queue system.
package queue

import (
	"container/heap"
	"sync"
	"time"
)

// PriorityQueue implements a min-heap for priority-based message scheduling.
type PriorityQueue []*ScheduleItem

// ScheduleItem wraps a message with scheduling metadata.
type ScheduleItem struct {
	Message   *Message
	Priority  int // Lower = higher priority
	Timestamp time.Time
	index     int // heap internal index
}

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	// Higher priority (lower number) first; break ties by timestamp
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority < pq[j].Priority
	}
	return pq[i].Timestamp.Before(pq[j].Timestamp)
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*ScheduleItem)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[:n-1]
	return item
}

// DomainBucket manages messages for a specific recipient domain,
// enforcing per-domain concurrency and rate limits.
type DomainBucket struct {
	Domain        string
	Queue         PriorityQueue
	ActiveCount   int
	MaxConcurrent int
	RateLimit     int // messages per second
	LastSend      time.Time
	Paused        bool
	PausedUntil   time.Time
	mu            sync.Mutex
}

// Scheduler manages domain-bucketed priority scheduling.
type Scheduler struct {
	buckets     map[string]*DomainBucket
	defaultConc int
	defaultRate int
	mu          sync.RWMutex
}

// NewScheduler creates a new delivery scheduler.
func NewScheduler(defaultConcurrency int, defaultRate int) *Scheduler {
	return &Scheduler{
		buckets:     make(map[string]*DomainBucket),
		defaultConc: defaultConcurrency,
		defaultRate: defaultRate,
	}
}

// Schedule adds a message to the appropriate domain bucket.
func (s *Scheduler) Schedule(msg *Message) {
	s.mu.Lock()
	bucket, exists := s.buckets[msg.Domain]
	if !exists {
		bucket = &DomainBucket{
			Domain:        msg.Domain,
			Queue:         make(PriorityQueue, 0),
			MaxConcurrent: s.defaultConc,
			RateLimit:     s.defaultRate,
		}
		heap.Init(&bucket.Queue)
		s.buckets[msg.Domain] = bucket
	}
	s.mu.Unlock()

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	heap.Push(&bucket.Queue, &ScheduleItem{
		Message:   msg,
		Priority:  msg.Priority,
		Timestamp: msg.CreatedAt,
	})
}

// Next returns the next message to deliver, respecting domain concurrency and rate limits.
// Returns nil if no messages are available for delivery.
func (s *Scheduler) Next() *Message {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()

	for _, bucket := range s.buckets {
		if msg := s.nextFromBucket(bucket, now); msg != nil {
			return msg
		}
	}

	return nil
}

// nextFromBucket attempts to dequeue one message from bucket, enforcing pause,
// concurrency, and rate-limit constraints. Returns nil if the bucket is not ready.
func (s *Scheduler) nextFromBucket(bucket *DomainBucket, now time.Time) *Message {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	if bucket.Paused {
		if now.Before(bucket.PausedUntil) {
			return nil
		}
		bucket.Paused = false
	}

	if bucket.ActiveCount >= bucket.MaxConcurrent {
		return nil
	}

	if bucket.RateLimit > 0 {
		interval := time.Second / time.Duration(bucket.RateLimit)
		if now.Sub(bucket.LastSend) < interval {
			return nil
		}
	}

	if bucket.Queue.Len() == 0 {
		return nil
	}

	item := heap.Pop(&bucket.Queue).(*ScheduleItem)
	bucket.ActiveCount++
	bucket.LastSend = now
	return item.Message
}

// Release marks a delivery attempt as complete, freeing a concurrency slot.
func (s *Scheduler) Release(domain string) {
	s.mu.RLock()
	bucket, exists := s.buckets[domain]
	s.mu.RUnlock()

	if !exists {
		return
	}

	bucket.mu.Lock()
	if bucket.ActiveCount > 0 {
		bucket.ActiveCount--
	}
	bucket.mu.Unlock()
}

// PauseDomain temporarily pauses delivery to a domain.
func (s *Scheduler) PauseDomain(domain string, duration time.Duration) {
	s.mu.RLock()
	bucket, exists := s.buckets[domain]
	s.mu.RUnlock()

	if !exists {
		return
	}

	bucket.mu.Lock()
	bucket.Paused = true
	bucket.PausedUntil = time.Now().Add(duration)
	bucket.mu.Unlock()
}

// SetDomainConcurrency sets the max concurrent connections for a domain.
func (s *Scheduler) SetDomainConcurrency(domain string, maxConc int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, exists := s.buckets[domain]
	if !exists {
		bucket = &DomainBucket{
			Domain:        domain,
			Queue:         make(PriorityQueue, 0),
			MaxConcurrent: maxConc,
			RateLimit:     s.defaultRate,
		}
		heap.Init(&bucket.Queue)
		s.buckets[domain] = bucket
		return
	}
	bucket.MaxConcurrent = maxConc
}

// Stats returns scheduling statistics for all domains.
func (s *Scheduler) Stats() map[string]DomainStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := make(map[string]DomainStats)
	for domain, bucket := range s.buckets {
		bucket.mu.Lock()
		stats[domain] = DomainStats{
			QueueDepth:  bucket.Queue.Len(),
			ActiveConns: bucket.ActiveCount,
			MaxConns:    bucket.MaxConcurrent,
			Paused:      bucket.Paused,
		}
		bucket.mu.Unlock()
	}
	return stats
}

// DomainStats holds statistics for a single domain bucket.
type DomainStats struct {
	QueueDepth  int  `json:"queue_depth"`
	ActiveConns int  `json:"active_conns"`
	MaxConns    int  `json:"max_conns"`
	Paused      bool `json:"paused"`
}

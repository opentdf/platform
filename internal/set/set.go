package set

type Set struct {
	set map[interface{}]struct{}
}

func NewSet() *Set {
	return &Set{set: make(map[interface{}]struct{})}
}

func (s *Set) Add(i interface{}) {
	s.set[i] = struct{}{}
}

func (s *Set) Remove(i interface{}) {
	delete(s.set, i)
}

func (s *Set) Contains(i interface{}) bool {
	_, ok := s.set[i]
	return ok
}

func (s *Set) Len() int {
	return len(s.set)
}

func (s *Set) ToSlice() []interface{} {
	slice := make([]interface{}, 0, len(s.set))
	for i := range s.set {
		slice = append(slice, i)
	}
	return slice
}

func (s *Set) Each(f func(interface{})) {
	for i := range s.set {
		f(i)
	}
}

func (s *Set) Iter() <-chan interface{} {
	ch := make(chan interface{})
	go func() {
		for i := range s.set {
			ch <- i
		}
		close(ch)
	}()
	return ch
}

func (s *Set) Union(other *Set) *Set {
	union := NewSet()
	for i := range s.set {
		union.Add(i)
	}
	for i := range other.set {
		union.Add(i)
	}
	return union
}

func (s *Set) Intersect(other *Set) *Set {
	intersect := NewSet()
	for i := range s.set {
		if other.Contains(i) {
			intersect.Add(i)
		}
	}
	return intersect
}

func (s *Set) Difference(other *Set) *Set {
	difference := NewSet()
	for i := range s.set {
		if !other.Contains(i) {
			difference.Add(i)
		}
	}
	return difference
}

func (s *Set) IsSubset(other *Set) bool {
	for i := range s.set {
		if !other.Contains(i) {
			return false
		}
	}
	return true
}

func (s *Set) IsSuperset(other *Set) bool {
	return other.IsSubset(s)
}

func (s *Set) Equal(other *Set) bool {
	return s.IsSubset(other) && s.IsSuperset(other)
}

func (s *Set) Clear() {
	s.set = make(map[interface{}]struct{})
}

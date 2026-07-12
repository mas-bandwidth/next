package common_test

import (
	"testing"

	"github.com/networknext/next/modules/common"

	"github.com/stretchr/testify/assert"
)

func TestSortedSet_Basic(t *testing.T) {

	t.Parallel()

	set := common.NewSortedSet()

	// insert returns true for new keys, false for existing

	assert.True(t, set.Insert(100, 5))
	assert.True(t, set.Insert(200, 3))
	assert.True(t, set.Insert(300, 7))
	assert.False(t, set.Insert(100, 5))

	// rank range walks ascending by score. start/end are 1-based, -1 means the end.

	nodes := set.GetByRankRange(1, -1)
	assert.Equal(t, 3, len(nodes))
	assert.Equal(t, uint64(200), nodes[0].Key)
	assert.Equal(t, uint64(100), nodes[1].Key)
	assert.Equal(t, uint64(300), nodes[2].Key)

	// re-inserting an existing key with a new score moves it

	assert.False(t, set.Insert(200, 9))
	nodes = set.GetByRankRange(1, -1)
	assert.Equal(t, 3, len(nodes))
	assert.Equal(t, uint64(100), nodes[0].Key)
	assert.Equal(t, uint64(300), nodes[1].Key)
	assert.Equal(t, uint64(200), nodes[2].Key)
	assert.Equal(t, uint32(9), nodes[2].Score)

	// equal scores order by key ascending

	set2 := common.NewSortedSet()
	assert.True(t, set2.Insert(30, 1))
	assert.True(t, set2.Insert(10, 1))
	assert.True(t, set2.Insert(20, 1))
	nodes = set2.GetByRankRange(1, -1)
	assert.Equal(t, uint64(10), nodes[0].Key)
	assert.Equal(t, uint64(20), nodes[1].Key)
	assert.Equal(t, uint64(30), nodes[2].Key)

	// partial rank ranges

	nodes = set2.GetByRankRange(1, 2)
	assert.Equal(t, 2, len(nodes))
	assert.Equal(t, uint64(10), nodes[0].Key)
	assert.Equal(t, uint64(20), nodes[1].Key)
}

func TestSortedSet_Large(t *testing.T) {

	t.Parallel()

	// insert a large number of keys with clustered scores (the cruncher usage pattern:
	// key = server/session id, score = bucket index) and verify full-range order

	set := common.NewSortedSet()

	const N = 10000

	for i := 0; i < N; i++ {
		assert.True(t, set.Insert(uint64(i*7919+1), uint32(i%256)))
	}

	nodes := set.GetByRankRange(1, -1)
	assert.Equal(t, N, len(nodes))

	for i := 1; i < len(nodes); i++ {
		if nodes[i-1].Score != nodes[i].Score {
			assert.Less(t, nodes[i-1].Score, nodes[i].Score)
		} else {
			assert.Less(t, nodes[i-1].Key, nodes[i].Key)
		}
	}
}

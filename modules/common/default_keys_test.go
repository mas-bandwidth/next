package common_test

import (
	"encoding/base64"
	"testing"

	"github.com/networknext/next/modules/common"
	db "github.com/networknext/next/modules/database"

	"github.com/stretchr/testify/assert"
)

func TestIsCommittedKey(t *testing.T) {

	t.Parallel()

	// the well-known test buyer keypair and local ping key must be detected

	assert.True(t, common.IsCommittedKey("AzcqXbdP3Txq3rHIjRBS4BfG7OoKV9PAZfB0rY7a+ArdizBzFAd2vQ=="))
	assert.True(t, common.IsCommittedKey("AzcqXbdP3TwX+9o9VfR7RcX2cq34UPdEsR2ztUnwxlTb/R49EiV5a2resciNEFLgF8bs6gpX08Bl8HStjtr4Ct2LMHMUB3a9"))
	assert.True(t, common.IsCommittedKey("xsBL4b6PO4ESADcc69kERzLXxs9ESOrX1kSHJH0m9D0="))

	// fresh keys must not be

	assert.False(t, common.IsCommittedKey(""))
	assert.False(t, common.IsCommittedKey("aGVsbG8gd29ybGQ="))
}

func TestDatabaseHasCommittedBuyerKey(t *testing.T) {

	t.Parallel()

	// a buyer with the well-known test buyer public key (32 byte raw key, after the 8 byte id prefix) is detected

	committed, err := base64.StdEncoding.DecodeString("AzcqXbdP3Txq3rHIjRBS4BfG7OoKV9PAZfB0rY7a+ArdizBzFAd2vQ==")
	assert.NoError(t, err)
	assert.Equal(t, 8+32, len(committed))

	database := db.CreateDatabase()
	database.BuyerMap[1] = &db.Buyer{Id: 1, Name: "test", PublicKey: committed[8:]}

	name, found := common.DatabaseHasCommittedBuyerKey(database)
	assert.True(t, found)
	assert.Equal(t, "test", name)

	// a buyer with a different key is not

	fresh := make([]byte, 32)
	for i := range fresh {
		fresh[i] = byte(i)
	}
	database.BuyerMap[1] = &db.Buyer{Id: 1, Name: "other", PublicKey: fresh}

	_, found = common.DatabaseHasCommittedBuyerKey(database)
	assert.False(t, found)
}

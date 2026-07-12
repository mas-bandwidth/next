package common

import (
	"encoding/base64"
	"os"

	"github.com/networknext/next/modules/core"
	db "github.com/networknext/next/modules/database"
	"github.com/networknext/next/modules/envvar"
)

// Every key below is committed to the network next source repository (envs/*.env,
// docker-compose.yml, terraform/staging/backend/terraform.tfvars), so anyone who can
// read the repo has them and they provide NO security at all. They exist for local
// development and functional tests only. `next keygen` regenerates every key for a
// real install -- this guard catches installs that skipped that step. Public halves
// are included because a matching public key implies the committed private half is in
// use. If a new key is ever committed by mistake, rotate it AND add it here.

var committedKeys = []string{

	// test buyer keypair (envs/*.env NEXT_BUYER_*, docker-compose.yml, staging tfvars load_test_buyer_private_key)
	"AzcqXbdP3Txq3rHIjRBS4BfG7OoKV9PAZfB0rY7a+ArdizBzFAd2vQ==",
	"AzcqXbdP3TwX+9o9VfR7RcX2cq34UPdEsR2ztUnwxlTb/R49EiV5a2resciNEFLgF8bs6gpX08Bl8HStjtr4Ct2LMHMUB3a9",

	// local relay backend keypair (envs/local.env, docker-compose.yml)
	"IsjRpWEz9H7qslhWWupW4A9LIpVh+PzWoLleuXL1NUE=",
	"qXeUdLPZxaMnZ/zFHLHkmgkQOmunWq1AmRv55nqTYMg=",

	// local server backend keypair (envs/local.env, docker-compose.yml)
	"1wXeogqOEL/UuMnHy3lwpdkdklcg4IktO/39mJiYfgc=",
	"peZ17P29VgtnOiEv5wwNPDDo9lWweFV7dBVac0KoaXHXBd6iCo4Qv9S4ycfLeXCl2R2SVyDgiS07/f2YmJh+Bw==",

	// local relay keypair (envs/local.env, staging tfvars relay_private_key)
	"1nTj7bQmo8gfIDqG+o//GFsak/g1TRo4hl6XXw1JkyI=",
	"cwvK44Pr5aHI3vE3siODS7CUgdPI/l1VwjVZ2FvEyAo=",

	// local ping key (envs/local.env, docker-compose.yml)
	"xsBL4b6PO4ESADcc69kERzLXxs9ESOrX1kSHJH0m9D0=",
}

// the env vars that carry key material into backend services

var keyEnvVars = []string{
	"NEXT_BUYER_PUBLIC_KEY",
	"NEXT_BUYER_PRIVATE_KEY",
	"RELAY_BACKEND_PUBLIC_KEY",
	"RELAY_BACKEND_PRIVATE_KEY",
	"NEXT_RELAY_BACKEND_PUBLIC_KEY",
	"SERVER_BACKEND_PUBLIC_KEY",
	"SERVER_BACKEND_PRIVATE_KEY",
	"NEXT_SERVER_BACKEND_PUBLIC_KEY",
	"RELAY_PUBLIC_KEY",
	"RELAY_PRIVATE_KEY",
	"PING_KEY",
	"API_PRIVATE_KEY",
}

func IsCommittedKey(value string) bool {
	for i := range committedKeys {
		if value == committedKeys[i] {
			return true
		}
	}
	return false
}

// DatabaseHasCommittedBuyerKey reports whether any buyer in the database uses the
// well-known test buyer keypair. Buyer.PublicKey is the raw 32 byte ed25519 key;
// the committed base64 value has an 8 byte buyer id prefix in front of it.
func DatabaseHasCommittedBuyerKey(database *db.Database) (string, bool) {
	for i := range committedKeys {
		value, err := base64.StdEncoding.DecodeString(committedKeys[i])
		if err != nil || len(value) != 8+32 {
			continue
		}
		key := value[8:]
		for _, buyer := range database.BuyerMap {
			if len(buyer.PublicKey) == len(key) && string(buyer.PublicKey) == string(key) {
				return buyer.Name, true
			}
		}
	}
	return "", false
}

// checkForCommittedKeys refuses to run in prod on keys committed to the source repo,
// and warns in dev/staging. local is exempt: local dev and the functional tests use
// the committed keys by design.

func (service *Service) checkForCommittedKeys() {

	if service.Env == "local" || service.Env == "" {
		return
	}

	for i := range keyEnvVars {
		value := envvar.GetString(keyEnvVars[i], "")
		if value == "" || !IsCommittedKey(value) {
			continue
		}
		if service.Env == "prod" {
			core.Error("%s is a well-known key committed to the network next source repository and cannot be used in prod. run 'next keygen' to generate keys for this install", keyEnvVars[i])
			os.Exit(1)
		}
		core.Warn("%s is a well-known key committed to the network next source repository. run 'next keygen' before going to prod", keyEnvVars[i])
	}
}

func (service *Service) checkDatabaseForCommittedKeys(database *db.Database) {

	if service.Env == "local" || service.Env == "" {
		return
	}

	buyerName, found := DatabaseHasCommittedBuyerKey(database)
	if !found {
		return
	}
	if service.Env == "prod" {
		core.Error("buyer '%s' in the database uses the well-known test buyer keypair committed to the network next source repository and cannot be used in prod. run 'next keygen' to generate keys for this install", buyerName)
		os.Exit(1)
	}
	core.Warn("buyer '%s' in the database uses the well-known test buyer keypair committed to the network next source repository. run 'next keygen' before going to prod", buyerName)
}

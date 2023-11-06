 /*
   Network Next Accelerate. Copyright © 2017 - 2023 Network Next, Inc. All rights reserved.
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	crypto_rand "crypto/rand"
	math_rand "math/rand"

	"github.com/networknext/next/modules/admin"
	"github.com/networknext/next/modules/common"
	"github.com/networknext/next/modules/constants"
	"github.com/networknext/next/modules/core"
	"github.com/networknext/next/modules/crypto"
	db "github.com/networknext/next/modules/database"

	"github.com/modood/table"
	"github.com/golang-jwt/jwt/v5"
	"github.com/peterbourgon/ff/v3/ffcli"
)

func main() {

	if !env.Exists() {
		env.Write()
	}
	env.Read()

	relaysfs := flag.NewFlagSet("relays state", flag.ExitOnError)
	var relaysCount int64
	relaysfs.Int64Var(&relaysCount, "n", 0, "Number of relays to display (default: all)")

	var relaysAlphaSort bool
	relaysfs.BoolVar(&relaysAlphaSort, "alpha", false, "Sort relays by name, not by sessions carried")

	var selectCommand = &ffcli.Command{
		Name:       "select",
		ShortUsage: "next select <local|dev|prod>",
		ShortHelp:  "Select environment to use (local|dev|staging|prod)",
		Exec: func(_ context.Context, args []string) error {
			if len(args) == 0 {
				handleRunTimeError(fmt.Sprintln("Provide an environment to switch to (local|dev|staging|prod)"), 0)
			}

			if args[0] == "local" {
				bashQuiet("rm -f database.bin && cp envs/local.bin database.bin")
				bashQuiet("psql -U developer postgres -f ../schemas/sql/destroy.sql")
				bashQuiet("psql -U developer postgres -f ../schemas/sql/create.sql")
				bashQuiet("psql -U developer postgres -f ../schemas/sql/local.sql")
			}

			envFilePath := fmt.Sprintf("envs/%s.env", args[0])

			if _, err := os.Stat(envFilePath); err != nil {
				return err
			}

			rawFile, err := os.Open(envFilePath)
			if err != nil {
				return err
			}

			defer rawFile.Close()

			rootEnvFile, err := os.Create(".env")
			if err != nil {
				return err
			}

			defer rootEnvFile.Close()

			if _, err = io.Copy(rootEnvFile, rawFile); err != nil {
				return err
			}

			env.Name = args[0]
			env.SSHKeyFile = getKeyValue(envFilePath, "SSH_KEY_FILE")
			env.API_URL = getKeyValue(envFilePath, "API_URL")
			env.PortalAPIKey = getKeyValue(envFilePath, "PORTAL_API_KEY")
			env.VPNAddress = getKeyValue(envFilePath, "VPN_ADDRESS")
			env.RelayBackendURL = getKeyValue(envFilePath, "RELAY_BACKEND_URL")
			env.RelayBackendPublicKey = getKeyValue(envFilePath, "RELAY_BACKEND_PUBLIC_KEY")
			env.RelayArtifactsBucketName = getKeyValue(envFilePath, "RELAY_ARTIFACTS_BUCKET_NAME")

			env.Write()

			cachedDatabase = nil
			if env.Name != "local" {
				bash("rm -f database.bin")
				getDatabase()
			}

			fmt.Printf("Selected %s environment\n\n", env.Name)

			return nil
		},
	}

	var keygenCommand = &ffcli.Command{
		Name:       "keygen",
		ShortUsage: "next keygen",
		ShortHelp:  "Generate new keypairs for network next",
		Exec: func(ctx context.Context, args []string) error {
			keygen(env, args)
			return nil
		},
	}

	var configCommand = &ffcli.Command{
		Name:       "config",
		ShortUsage: "next config",
		ShortHelp:  "Configure network next",
		Exec: func(ctx context.Context, args []string) error {
			config(env, args)
			return nil
		},
	}

	var secretsCommand = &ffcli.Command{
		Name:       "secrets",
		ShortUsage: "next secrets",
		ShortHelp:  "Zip up secrets directory",
		Exec: func(ctx context.Context, args []string) error {
			secrets()
			return nil
		},
	}

	var envCommand = &ffcli.Command{
		Name:       "env",
		ShortUsage: "next env",
		ShortHelp:  "Display environment",
		Exec: func(_ context.Context, args []string) error {
			if len(args) > 0 {
				env.Name = args[0]
				env.Write()
				fmt.Printf("Selected %s environment\n", env.Name)
			}
			fmt.Print(env.String())
			fmt.Printf("\n")
			return nil
		},
	}

	var pingCommand = &ffcli.Command{
		Name:       "ping",
		ShortUsage: "next ping",
		ShortHelp:  "Ping the REST API in the current environment",
		Exec: func(_ context.Context, args []string) error {
			ping()
			return nil
		},
	}

	var databaseCommand = &ffcli.Command{
		Name:       "database",
		ShortUsage: "next database",
		ShortHelp:  "Update local database.bin from the current environment Postgres DB and print it",
		Exec: func(_ context.Context, args []string) error {
			printDatabase()
			return nil
		},
	}

	var commitCommand = &ffcli.Command{
		Name:       "commit",
		ShortUsage: "next commit",
		ShortHelp:  "Commit the local database.bin to the current environment runtime (server and relay backends)",
		Exec: func(_ context.Context, args []string) error {
			commitDatabase()
			return nil
		},
	}

	var relaysCommand = &ffcli.Command{
		Name:       "relays",
		ShortUsage: "next relays <regex>",
		ShortHelp:  "List relays in the current environment",
		FlagSet:    relaysfs,
		Exec: func(_ context.Context, args []string) error {

			var regexName string
			if len(args) > 0 {
				regexName = args[0]
			}

			printRelays(env, relaysCount, relaysAlphaSort, regexName)

			return nil
		},
	}

	var sshCommand = &ffcli.Command{
		Name:       "ssh",
		ShortUsage: "next ssh [regex...]",
		ShortHelp:  "SSH into the specified relay(s)",
		Exec: func(_ context.Context, args []string) error {
			regexes := []string{".*"}
			if len(args) > 0 {
				regexes = args
			}

			ssh(env, regexes)

			return nil
		},
	}

	var logCommand = &ffcli.Command{
		Name:       "logs",
		ShortUsage: "next logs <regex> [regex]",
		ShortHelp:  "View the journalctl log for a relay",
		Exec: func(ctx context.Context, args []string) error {

			if len(args) == 0 {
				handleRunTimeError(fmt.Sprintln("you must supply at least one argument"), 0)
			}

			relayLog(env, args)

			return nil
		},
	}

	var setupCommand = &ffcli.Command{
		Name:       "setup",
		ShortUsage: "next setup [regex...]",
		ShortHelp:  "Setup the specified relay(s)",
		Exec: func(_ context.Context, args []string) error {
			regexes := []string{".*"}
			if len(args) > 0 {
				regexes = args
			}

			setupRelays(env, regexes)

			return nil
		},
	}

	var startCommand = &ffcli.Command{
		Name:       "start",
		ShortUsage: "next start [regex...]",
		ShortHelp:  "Start the specified relay(s)",
		Exec: func(_ context.Context, args []string) error {
			regexes := []string{".*"}
			if len(args) > 0 {
				regexes = args
			}

			startRelays(env, regexes)

			return nil
		},
	}

	var stopCommand = &ffcli.Command{
		Name:       "stop",
		ShortUsage: "next stop [regex...]",
		ShortHelp:  "Stop the specified relay(s)",
		Exec: func(_ context.Context, args []string) error {
			regexes := []string{".*"}
			if len(args) > 0 {
				regexes = args
			}

			stopRelays(env, regexes)

			return nil
		},
	}

	var upgradeCommand = &ffcli.Command{
		Name:       "upgrade",
		ShortUsage: "next upgrade [regex...]",
		ShortHelp:  "Upgrade the specified relay(s)",
		Exec: func(_ context.Context, args []string) error {
			regexes := []string{".*"}
			if len(args) > 0 {
				regexes = args
			}

			upgradeRelays(env, regexes)

			return nil
		},
	}

	var rebootCommand = &ffcli.Command{
		Name:       "reboot",
		ShortUsage: "next reboot [regex...]",
		ShortHelp:  "Reboot the specified relay(s)",
		Exec: func(_ context.Context, args []string) error {
			regexes := []string{".*"}
			if len(args) > 0 {
				regexes = args
			}

			rebootRelays(env, regexes)

			return nil
		},
	}

	var loadCommand = &ffcli.Command{
		Name:       "load",
		ShortUsage: "next load [version] [regex...]",
		ShortHelp:  "Load the specific relay binary version onto one or more relays",
		Exec: func(_ context.Context, args []string) error {
			if len(args) < 1 {
				handleRunTimeError(fmt.Sprintf("Please provide a version"), 0)
			}
			version := args[0]
			regexes := []string{".*"}
			if len(args) > 1 {
				regexes = args[1:]
			}

			loadRelays(env, regexes, version)

			return nil
		},
	}

	var costCommand = &ffcli.Command{
		Name:       "cost",
		ShortUsage: "next cost [output_file]",
		ShortHelp:  "Get cost matrix from current environment",
		Exec: func(ctx context.Context, args []string) error {
			output := "cost.bin"
			if len(args) > 0 {
				output = args[0]
			}
			getCostMatrix(env, output)
			fmt.Printf("Cost matrix from %s saved to %s\n\n", env.Name, output)
			return nil
		},
	}

	var optimizeCommand = &ffcli.Command{
		Name:       "optimize",
		ShortUsage: "next optimize [rtt] [input_file] [output_file]",
		ShortHelp:  "Optimize cost matrix into a route matrix",
		Exec: func(ctx context.Context, args []string) error {
			input := "cost.bin"
			output := "optimize.bin"
			rtt := int32(1)

			if len(args) > 0 {
				if res, err := strconv.ParseInt(args[0], 10, 32); err == nil {
					rtt = int32(res)
				} else {
					handleRunTimeError(fmt.Sprintf("could not parse 1st argument to number: %v\n", err), 1)
				}
			}

			if len(args) > 1 {
				input = args[1]
			}

			if len(args) > 2 {
				output = args[2]
			}

			optimizeCostMatrix(input, output, rtt)

			fmt.Printf("Generated route matrix %s from %s\n\n", output, input)

			return nil
		},
	}

	var analyzeCommand = &ffcli.Command{
		Name:       "analyze",
		ShortUsage: "next analyze <input_file>",
		ShortHelp:  "Analyze route matrix from optimize",
		Exec: func(ctx context.Context, args []string) error {
			input := "optimize.bin"
			if len(args) > 0 {
				input = args[0]
			}
			analyzeRouteMatrix(input)
			return nil
		},
	}

	var routesCommand = &ffcli.Command{
		Name:       "routes",
		ShortUsage: "next routes [src] [dest]",
		ShortHelp:  "Print list of routes from one relay to another",
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 2 {
				handleRunTimeError(fmt.Sprintf("Please provide source and destination relay names"), 0)
			}
			src := args[0]
			dest := args[1]
			routes(src, dest)
			return nil
		},
	}

	var commands = []*ffcli.Command{
		keygenCommand,
		configCommand,
		secretsCommand,
		selectCommand,
		envCommand,
		pingCommand,
		databaseCommand,
		commitCommand,
		relaysCommand,
		sshCommand,
		logCommand,
		setupCommand,
		startCommand,
		stopCommand,
		loadCommand,
		upgradeCommand,
		rebootCommand,
		costCommand,
		optimizeCommand,
		analyzeCommand,
		routesCommand,
	}

	root := &ffcli.Command{
		ShortUsage:  "next <subcommand>",
		Subcommands: commands,
		Exec: func(context.Context, []string) error {
			fmt.Printf("Network Next Operator Tool\n\n")
			return nil
		},
	}

	fmt.Printf("\n")

	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--h" || args[0] == "--help" {
		args = []string{}
	}

	if err := root.ParseAndRun(context.Background(), args); err != nil {
		fmt.Printf("\n")
		handleRunTimeError(fmt.Sprintf("%v\n", err), 1)
	}

	if len(args) == 0 {
		root.FlagSet.Usage()
	}
}

// ------------------------------------------------------------------------------

func replace(filename string, pattern string, replacement string) {

	r, err := regexp.Compile(pattern)
	if err != nil {
		panic(fmt.Errorf("could not compile regex: %v", pattern))
	}

	inputFile := filename

	outputFile := filename + ".tmp"

	input, err := os.ReadFile(inputFile)
   if err != nil {
		panic(fmt.Errorf("could not read input file: %v", inputFile))
   }

   lines := strings.Split(string(input), "\n")

	output, err := os.Create(outputFile)
	if err != nil {
		panic(fmt.Errorf("could not open output file: %v", outputFile))
	}

   for i := range lines {
   	if i == len(lines) - 1 && lines[i] == "" {
   		break
   	}
   	if r.MatchString(lines[i]) {
   		fmt.Fprintf(output, "%s\n", replacement)
   	} else {
	   	fmt.Fprintf(output, "%s\n", lines[i])
   	}
   }

   output.Close()

   err = os.Rename(outputFile, inputFile)
   if err != nil {
   	panic(fmt.Errorf("could not move output file to input file: %v", err))
   }
}

func generateBuyerKeypair() (buyerPublicKey []byte, buyerPrivateKey []byte) {

	buyerId := make([]byte, 8)
	crypto_rand.Read(buyerId)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Printf("failed to generate keypair: %v", err)
		os.Exit(1)
	}

	buyerPublicKey = make([]byte, 0)
	buyerPublicKey = append(buyerPublicKey, buyerId...)
	buyerPublicKey = append(buyerPublicKey, publicKey...)

	buyerPrivateKey = make([]byte, 0)
	buyerPrivateKey = append(buyerPrivateKey, buyerId...)
	buyerPrivateKey = append(buyerPrivateKey, privateKey...)

	return
}

func writeSecret(k string, v map[string]string, name string) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("\nerror: could not get user home dir: %v\n\n", err)
		os.Exit(1)
	}
	adjustedName := strings.Replace(name, "_", "-", -1)
	filename := fmt.Sprintf("%s/secrets/%s-%s.txt", homeDir, k, adjustedName)
	fmt.Printf("   ~/secrets/%s-%s.txt\n", k, adjustedName)
	err = os.WriteFile(filename, []byte(v[name]), 0666)
	if err != nil {
		fmt.Printf("\nerror: failed to write secret: %v\n\n", err)
		os.Exit(1)
	}
}

func secretsAlreadyExist() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("\nerror: could not get user home dir: %v\n\n", err)
		os.Exit(1)
	}
	filename := fmt.Sprintf("%s/secrets/local-relay-backend-public-key.txt", homeDir)
	return fileExists(filename)
}

func keygen(env Environment, regexes []string) {
		
	math_rand.Seed(time.Now().UnixNano())

	if secretsAlreadyExist() {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("*** WARNING ***\n\nSecrets already exist.\n\nRunning keygen will overwrite your secrets, and you'll lose control of any system that you've already deployed.\n\nAre you sure you want to continue? (yes/no): ")
		text, _ := reader.ReadString('\n')
		if strings.TrimSpace(text) != "yes" {
			fmt.Printf("\nAborted.\n\n")
			os.Exit(1)
		}
	}

	fmt.Printf("------------------------------------------\n           generating keypairs\n------------------------------------------\n\n")

	bash("mkdir -p ~/secrets")

   envs := []string{"local", "dev", "staging", "prod"}

	keypairs := make(map[string]map[string]string)

	testRelayPublicKey, testRelayPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		fmt.Printf("\nerror: failed to generate relay keypair\n\n")
		os.Exit(1)
	}

	testBuyerPublicKey, testBuyerPrivateKey := generateBuyerKeypair()

	raspberryBuyerPublicKey, raspberryBuyerPrivateKey := generateBuyerKeypair()

	fmt.Printf("global:\n\n")

	fmt.Printf("	Test relay public key          = %s\n", base64.StdEncoding.EncodeToString(testRelayPublicKey[:]))
	fmt.Printf("	Test relay private key         = %s\n", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:]))

	fmt.Printf("	Test buyer public key          = %s\n", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:]))
	fmt.Printf("	Test buyer private key         = %s\n", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:]))

	fmt.Printf("	Raspberry buyer public key     = %s\n", base64.StdEncoding.EncodeToString(raspberryBuyerPublicKey[:]))
	fmt.Printf("	Raspberry buyer private key    = %s\n", base64.StdEncoding.EncodeToString(raspberryBuyerPrivateKey[:]))

	fmt.Printf("\n")

   for i := range envs {

   	fmt.Printf("%s:\n\n", envs[i])

		relayBackendPublicKey, relayBackendPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
		if err != nil {
			fmt.Printf("\nerror: failed to generate relay backend keypair\n\n")
			os.Exit(1)
		}

		serverBackendPublicKey, serverBackendPrivateKey := crypto.Sign_KeyPair()

		apiPrivateKey := common.RandomStringFixedLength(64)

		type Claims struct {
			Admin  bool `json:"admin"`
			Portal bool `json:"portal"`
			jwt.RegisteredClaims			
		}

		adminClaims := Claims{
			true, 
			true,
			jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now()), 
				Issuer: "next keygen",
			},
		}
		adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
		adminAPIKey, err := adminToken.SignedString([]byte(apiPrivateKey))
		if err != nil {
			fmt.Printf("\nerror: could not generate admin api key: %v\n\n", err)
			os.Exit(1)
		}

		portalClaims := Claims{
			false, 
			true,
			jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now()), 
				Issuer: "next keygen",
			},
		}
		portalToken := jwt.NewWithClaims(jwt.SigningMethodHS256, portalClaims)
		portalAPIKey, err := portalToken.SignedString([]byte(apiPrivateKey))
		if err != nil {
			fmt.Printf("\nerror: could not generate portal api key: %v\n\n", err)
			os.Exit(1)
		}

		pingKey := [32]byte{}
		common.RandomBytes(pingKey[:])

		fmt.Printf("	Relay backend public key       = %s\n", base64.StdEncoding.EncodeToString(relayBackendPublicKey[:]))
		fmt.Printf("	Relay backend private key      = %s\n", base64.StdEncoding.EncodeToString(relayBackendPrivateKey[:]))
		fmt.Printf("	Server backend public key      = %s\n", base64.StdEncoding.EncodeToString(serverBackendPublicKey[:]))
		fmt.Printf("	Server backend private key     = %s\n", base64.StdEncoding.EncodeToString(serverBackendPrivateKey[:]))
		fmt.Printf("	API private key                = %s\n", apiPrivateKey)
		fmt.Printf("	Admin API key                  = %s\n", portalAPIKey)
		fmt.Printf("	Portal API key                 = %s\n", adminAPIKey)
		fmt.Printf("	Ping key                       = %s\n\n", base64.StdEncoding.EncodeToString(pingKey[:]))

   	m := make(map[string]string)

   	m["relay_backend_public_key"] = base64.StdEncoding.EncodeToString(relayBackendPublicKey[:])
   	m["relay_backend_private_key"] = base64.StdEncoding.EncodeToString(relayBackendPrivateKey[:])
   	m["server_backend_public_key"] = base64.StdEncoding.EncodeToString(serverBackendPublicKey[:])
   	m["server_backend_private_key"] = base64.StdEncoding.EncodeToString(serverBackendPrivateKey[:])
   	m["api_private_key"] = apiPrivateKey
   	m["admin_api_key"] = adminAPIKey
   	m["portal_api_key"] = portalAPIKey
   	m["ping_key"] = base64.StdEncoding.EncodeToString(pingKey[:])

   	keypairs[envs[i]] = m
	}

	// mark all envs except local as secure. this puts their private keys under ~/secrets instead of the .env file

	for k,v := range keypairs {
		if k != "local" {
			v["secure"] = "true"
		}
	}

	// write secrets

	fmt.Printf("------------------------------------------\n             writing secrets\n------------------------------------------\n\n")

	for k,v := range keypairs {

   	fmt.Printf("%s:\n\n", k)

   	writeSecret(k, v, "relay_backend_public_key")
   	writeSecret(k, v, "relay_backend_private_key")
   	writeSecret(k, v, "server_backend_public_key")
   	writeSecret(k, v, "server_backend_private_key")
   	writeSecret(k, v, "api_private_key")
   	writeSecret(k, v, "admin_api_key")
   	writeSecret(k, v, "portal_api_key")
   	writeSecret(k, v, "ping_key")

		fmt.Printf("\n")
	}

   // update non-secret keys in env files

	fmt.Printf("------------------------------------------\n           updating env files\n------------------------------------------\n\n")

   for k,v := range keypairs {
   	envFile := fmt.Sprintf("envs/%s.env", k)
	   fmt.Printf("%s\n", envFile)
	   {
		   replace(envFile, "^\\s*PORTAL_API_KEY\\s*=.*$", fmt.Sprintf("PORTAL_API_KEY=\"%s\"", v["portal_api_key"]))
		   replace(envFile, "^\\s*RELAY_BACKEND_PUBLIC_KEY\\s*=.*$", fmt.Sprintf("RELAY_BACKEND_PUBLIC_KEY=\"%s\"", v["relay_backend_public_key"]))
		   replace(envFile, "^\\s*SERVER_BACKEND_PUBLIC_KEY\\s*=.*$", fmt.Sprintf("SERVER_BACKEND_PUBLIC_KEY=\"%s\"", v["server_backend_public_key"]))
		   replace(envFile, "^\\s*NEXT_RELAY_BACKEND_PUBLIC_KEY\\s*=.*$", fmt.Sprintf("NEXT_RELAY_BACKEND_PUBLIC_KEY=\"%s\"", v["relay_backend_public_key"]))
		   replace(envFile, "^\\s*NEXT_SERVER_BACKEND_PUBLIC_KEY\\s*=.*$", fmt.Sprintf("NEXT_SERVER_BACKEND_PUBLIC_KEY=\"%s\"", v["server_backend_public_key"]))
		   replace(envFile, "^\\s*NEXT_BUYER_PUBLIC_KEY\\s*=.*$", fmt.Sprintf("NEXT_BUYER_PUBLIC_KEY=\"%s\"", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
		   replace(envFile, "^\\s*NEXT_BUYER_PRIVATE_KEY\\s*=.*$", fmt.Sprintf("NEXT_BUYER_PRIVATE_KEY=\"%s\"", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:])))
		   replace(envFile, "^\\s*RELAY_PUBLIC_KEY\\s*=.*$", fmt.Sprintf("RELAY_PUBLIC_KEY=\"%s\"", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
		   replace(envFile, "^\\s*RELAY_PRIVATE_KEY\\s*=.*$", fmt.Sprintf("RELAY_PRIVATE_KEY=\"%s\"", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))

		   if v["secure"] != "true" {
			   replace(envFile, "^\\s*API_PRIVATE_KEY\\s*=.*$", fmt.Sprintf("API_PRIVATE_KEY=\"%s\"", v["api_private_key"]))
			   replace(envFile, "^\\s*RELAY_BACKEND_PRIVATE_KEY\\s*=.*$", fmt.Sprintf("RELAY_BACKEND_PRIVATE_KEY=\"%s\"", v["relay_backend_private_key"]))
			   replace(envFile, "^\\s*SERVER_BACKEND_PRIVATE_KEY\\s*=.*$", fmt.Sprintf("SERVER_BACKEND_PRIVATE_KEY=\"%s\"", v["server_backend_private_key"]))
			   replace(envFile, "^\\s*PING_KEY\\s*=.*$", fmt.Sprintf("PING_KEY=\"%s\"", v["ping_key"]))
		   }
		}
   }

   // update non-secret keys in terraform files

	fmt.Printf("\n------------------------------------------\n        updating terraform files\n------------------------------------------\n\n")

   for k,v := range keypairs {

   	filenames := []string {
   		fmt.Sprintf("terraform/%s/backend/terraform.tfvars", k),
   		fmt.Sprintf("terraform/%s/relays/terraform.tfvars", k),
   	}
   	for i := range filenames {
   		if fileExists(filenames[i]) {
	   		fmt.Printf("%s\n", filenames[i])
			   replace(filenames[i], "^\\s*relay_backend_public_key\\s*=.*$",    fmt.Sprintf("relay_backend_public_key    = \"%s\"", v["relay_backend_public_key"]))
			   replace(filenames[i], "^\\s*server_backend_public_key\\s*=.*$",   fmt.Sprintf("server_backend_public_key   = \"%s\"", v["server_backend_public_key"]))
				replace(filenames[i], "^\\s*test_buyer_public_key\\s*=.*$",       fmt.Sprintf("test_buyer_public_key       = \"%s\"", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
				replace(filenames[i], "^\\s*raspberry_buyer_public_key\\s*=.*$",  fmt.Sprintf("raspberry_buyer_public_key  = \"%s\"", base64.StdEncoding.EncodeToString(raspberryBuyerPublicKey[:])))
				replace(filenames[i], "^\\s*raspberry_buyer_private_key\\s*=.*$", fmt.Sprintf("raspberry_buyer_private_key = \"%s\"", base64.StdEncoding.EncodeToString(raspberryBuyerPrivateKey[:])))
				replace(filenames[i], "^\\s*load_test_buyer_public_key\\s*=.*$",  fmt.Sprintf("load_test_buyer_public_key  = \"%s\"", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
				replace(filenames[i], "^\\s*load_test_buyer_private_key\\s*=.*$", fmt.Sprintf("load_test_buyer_private_key = \"%s\"", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:])))
				replace(filenames[i], "^\\s*relay_public_key\\s*=.*$",  fmt.Sprintf("relay_public_key  = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
				replace(filenames[i], "^\\s*relay_private_key\\s*=.*$", fmt.Sprintf("relay_private_key = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
   		}
   	}

   	filenames = []string {
   		fmt.Sprintf("terraform/%s/relays/main.tf", k),
   	}

   	for i := range filenames {
   		if fileExists(filenames[i]) {
	   		fmt.Printf("%s\n", filenames[i])
			   replace(filenames[i], "^\\s*api_key\\s*=.*$",             fmt.Sprintf("  api_key  = \"%s\"", v["admin_api_key"]))	
   		}
   	}
	}

   // update non-secret keys in source files

	fmt.Printf("\n------------------------------------------\n          updating source files\n------------------------------------------\n\n")

	fmt.Printf("sdk/include/next_config.h\n")
   {
   	replace("sdk/include/next_config.h", "^\\s*\\#define NEXT_PROD_SERVER_BACKEND_PUBLIC_KEY.*$", fmt.Sprintf("#define NEXT_PROD_SERVER_BACKEND_PUBLIC_KEY \"%s\"", keypairs["prod"]["server_backend_public_key"]))
   	replace("sdk/include/next_config.h", "^\\s*\\#define NEXT_PROD_RELAY_BACKEND_PUBLIC_KEY.*$", fmt.Sprintf("#define NEXT_PROD_RELAY_BACKEND_PUBLIC_KEY \"%s\"", keypairs["prod"]["relay_backend_public_key"]))
   	replace("sdk/include/next_config.h", "^\\s*\\#define NEXT_DEV_SERVER_BACKEND_PUBLIC_KEY.*$", fmt.Sprintf("#define NEXT_DEV_SERVER_BACKEND_PUBLIC_KEY \"%s\"", keypairs["dev"]["server_backend_public_key"]))
   	replace("sdk/include/next_config.h", "^\\s*\\#define NEXT_DEV_RELAY_BACKEND_PUBLIC_KEY.*$", fmt.Sprintf("#define NEXT_DEV_RELAY_BACKEND_PUBLIC_KEY \"%s\"", keypairs["dev"]["relay_backend_public_key"]))
   }

	fmt.Printf("sdk/soak.cpp\n")
	{
	   replace("sdk/soak.cpp", "^\\s*const char \\* buyer_public_key =.*$", fmt.Sprintf("const char * buyer_public_key = \"%s\";", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:])))
	   replace("sdk/soak.cpp", "^\\s*const char \\* buyer_private_key =.*$", fmt.Sprintf("const char * buyer_private_key = \"%s\";", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:])))
	}

	fmt.Printf("cmd/raspberry_client/raspberry_client.cpp\n")
	{
	   replace("cmd/raspberry_client/raspberry_client.cpp", "^\\s*strncpy_s\\(config\\.buyer_public_key,.*$", fmt.Sprintf("    strncpy_s(config.buyer_public_key, \"%s\", 256);", base64.StdEncoding.EncodeToString(raspberryBuyerPublicKey[:])))
	   replace("cmd/raspberry_client/raspberry_client.cpp", "^\\s*strncpy\\(config\\.buyer_public_key,.*$", fmt.Sprintf("    strncpy(config.buyer_public_key, \"%s\", 256);", base64.StdEncoding.EncodeToString(raspberryBuyerPublicKey[:])))
	}

	fmt.Printf("sdk/examples/upgraded_client.cpp\n")
	{
	   replace("sdk/examples/upgraded_client.cpp", "^\\s*const char \\* buyer_public_key =.*$", fmt.Sprintf("const char * buyer_public_key = \"%s\";", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
	}

	fmt.Printf("sdk/examples/upgraded_server.cpp\n")
	{
	   replace("sdk/examples/upgraded_server.cpp", "^\\s*const char \\* buyer_private_key =.*$", fmt.Sprintf("const char * buyer_private_key = \"%s\";", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:])))
	}

	fmt.Printf("sdk/examples/complex_client.cpp\n")
	{
	   replace("sdk/examples/complex_client.cpp", "^\\s*const char \\* buyer_public_key =.*$", fmt.Sprintf("const char * buyer_public_key = \"%s\";", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
	}

	fmt.Printf("sdk/examples/complex_server.cpp\n")
	{
	   replace("sdk/examples/complex_server.cpp", "^\\s*const char \\* buyer_private_key =.*$", fmt.Sprintf("const char * buyer_private_key = \"%s\";", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:])))
	}

	fmt.Printf("docker-compose.yml\n")
	{
	   replace("docker-compose.yml", "^\\s* - RELAY_BACKEND_PUBLIC_KEY=.*$",   fmt.Sprintf("      - RELAY_BACKEND_PUBLIC_KEY=%s", keypairs["local"]["relay_backend_public_key"]))
	   replace("docker-compose.yml", "^\\s* - RELAY_BACKEND_PRIVATE_KEY=.*$",  fmt.Sprintf("      - RELAY_BACKEND_PRIVATE_KEY=%s", keypairs["local"]["relay_backend_private_key"]))
	   replace("docker-compose.yml", "^\\s* - SERVER_BACKEND_PUBLIC_KEY=.*$",  fmt.Sprintf("      - SERVER_BACKEND_PUBLIC_KEY=%s", keypairs["local"]["server_backend_public_key"]))
	   replace("docker-compose.yml", "^\\s* - SERVER_BACKEND_PRIVATE_KEY=.*$", fmt.Sprintf("      - SERVER_BACKEND_PRIVATE_KEY=%s", keypairs["local"]["server_backend_private_key"]))
	   replace("docker-compose.yml", "^\\s* - PING_KEY=.*$",                   fmt.Sprintf("      - PING_KEY=%s", keypairs["local"]["ping_key"]))
	   replace("docker-compose.yml", "^\\s* - NEXT_BUYER_PUBLIC_KEY=.*$",      fmt.Sprintf("      - NEXT_BUYER_PUBLIC_KEY=%s", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
	   replace("docker-compose.yml", "^\\s* - NEXT_BUYER_PRIVATE_KEY=.*$",     fmt.Sprintf("      - NEXT_BUYER_PRIVATE_KEY=%s", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:])))
	   replace("docker-compose.yml", "^\\s* - RELAY_PUBLIC_KEY=.*$",           fmt.Sprintf("      - RELAY_PUBLIC_KEY=%s", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
	   replace("docker-compose.yml", "^\\s* - RELAY_PRIVATE_KEY=.*$",          fmt.Sprintf("      - RELAY_PRIVATE_KEY=%s", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
	}

	fmt.Printf("schemas/sql/local.sql\n")
	{
	   replace("schemas/sql/local.sql", "^SET local.buyer_public_key_base64 = '.*$",   fmt.Sprintf("SET local.buyer_public_key_base64 = '%s';", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
	   replace("schemas/sql/local.sql", "^SET local.relay_public_key_base64 = '.*$",   fmt.Sprintf("SET local.relay_public_key_base64 = '%s';", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
	   replace("schemas/sql/local.sql", "^SET local.relay_private_key_base64 = '.*$",   fmt.Sprintf("SET local.relay_private_key_base64 = '%s';", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
	}

	fmt.Printf("schemas/sql/docker.sql\n")
	{
	   replace("schemas/sql/docker.sql", "^SET local.buyer_public_key_base64 = '.*$",   fmt.Sprintf("SET local.buyer_public_key_base64 = '%s';", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
	   replace("schemas/sql/docker.sql", "^SET local.relay_public_key_base64 = '.*$",   fmt.Sprintf("SET local.relay_public_key_base64 = '%s';", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
	   replace("schemas/sql/docker.sql", "^SET local.relay_private_key_base64 = '.*$",   fmt.Sprintf("SET local.relay_private_key_base64 = '%s';", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
	}

	fmt.Printf("tools/generate_staging_sql/generate_staging_sql.go\n")
	{
	   replace("tools/generate_staging_sql/generate_staging_sql.go", "const BuyerPublicKeyBase64 = \".*$",   fmt.Sprintf("const BuyerPublicKeyBase64 = \"%s\"", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
	   replace("tools/generate_staging_sql/generate_staging_sql.go", "const RelayPublicKeyBase64 = \".*$",   fmt.Sprintf("const RelayPublicKeyBase64 = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
	   replace("tools/generate_staging_sql/generate_staging_sql.go", "const RelayPrivateKeyBase64 = \".*$",   fmt.Sprintf("const RelayPrivateKeyBase64 = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
	}

	fmt.Printf("cmd/func_test_api/func_test_api.go\n")
	{
	   replace("cmd/func_test_api/func_test_api.go", "const TestAPIKey = \".*$",   fmt.Sprintf("const TestAPIKey = \"%s\"", keypairs["local"]["admin_api_key"]))
	   replace("cmd/func_test_api/func_test_api.go", "const TestAPIPrivateKey = \".*$",   fmt.Sprintf("const TestAPIPrivateKey = \"%s\"", keypairs["local"]["api_private_key"]))
	   replace("cmd/func_test_api/func_test_api.go", "const TestBuyerPublicKey = \".*$",   fmt.Sprintf("const TestBuyerPublicKey = \"%s\"", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
	}

	fmt.Printf("cmd/func_test_database/func_test_database.go\n")
	{
	   replace("cmd/func_test_database/func_test_database.go", "const TestAPIKey = \".*$",   fmt.Sprintf("const TestAPIKey = \"%s\"", keypairs["local"]["admin_api_key"]))
	   replace("cmd/func_test_database/func_test_database.go", "const TestAPIPrivateKey = \".*$",   fmt.Sprintf("const TestAPIPrivateKey = \"%s\"", keypairs["local"]["api_private_key"]))
	}

	fmt.Printf("cmd/func_test_portal/func_test_portal.go\n")
	{
	   replace("cmd/func_test_portal/func_test_portal.go", "const TestAPIKey = \".*$",   fmt.Sprintf("const TestAPIKey = \"%s\"", keypairs["local"]["admin_api_key"]))
	   replace("cmd/func_test_portal/func_test_portal.go", "const TestAPIPrivateKey = \".*$",   fmt.Sprintf("const TestAPIPrivateKey = \"%s\"", keypairs["local"]["api_private_key"]))
	}

	fmt.Printf("cmd/func_test_sdk/func_test_sdk.go\n")
	{
	   replace("cmd/func_test_sdk/func_test_sdk.go", "const TestRelayPublicKey = \".*$",   fmt.Sprintf("const TestRelayPublicKey = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
	   replace("cmd/func_test_sdk/func_test_sdk.go", "const TestRelayPrivateKey = \".*$",  fmt.Sprintf("const TestRelayPrivateKey = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
	   replace("cmd/func_test_sdk/func_test_sdk.go", "const TestBuyerPublicKey = \".*$",   fmt.Sprintf("const TestBuyerPublicKey = \"%s\"", base64.StdEncoding.EncodeToString(testBuyerPublicKey[:])))
	   replace("cmd/func_test_sdk/func_test_sdk.go", "const TestBuyerPrivateKey = \".*$",  fmt.Sprintf("const TestBuyerPrivateKey = \"%s\"", base64.StdEncoding.EncodeToString(testBuyerPrivateKey[:])))
	   replace("cmd/func_test_sdk/func_test_sdk.go", "const TestRelayBackendPublicKey = \".*$",  fmt.Sprintf("const TestRelayBackendPublicKey = \"%s\"", keypairs["local"]["relay_backend_public_key"]))
	   replace("cmd/func_test_sdk/func_test_sdk.go", "const TestRelayBackendPrivateKey = \".*$",  fmt.Sprintf("const TestRelayBackendPrivateKey = \"%s\"", keypairs["local"]["relay_backend_private_key"]))
	   replace("cmd/func_test_sdk/func_test_sdk.go", "const TestServerBackendPublicKey = \".*$",  fmt.Sprintf("const TestServerBackendPublicKey = \"%s\"", keypairs["local"]["server_backend_public_key"]))
	   replace("cmd/func_test_sdk/func_test_sdk.go", "const TestServerBackendPrivateKey = \".*$",  fmt.Sprintf("const TestServerBackendPrivateKey = \"%s\"", keypairs["local"]["server_backend_private_key"]))
	}

	fmt.Printf("cmd/func_test_relay/func_test_relay.go\n")
	{
	   replace("cmd/func_test_relay/func_test_relay.go", "const TestRelayPublicKey = \".*$",   fmt.Sprintf("const TestRelayPublicKey = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
	   replace("cmd/func_test_relay/func_test_relay.go", "const TestRelayPrivateKey = \".*$",  fmt.Sprintf("const TestRelayPrivateKey = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
	   replace("cmd/func_test_relay/func_test_relay.go", "const TestRelayBackendPublicKey = \".*$",  fmt.Sprintf("const TestRelayBackendPublicKey = \"%s\"", keypairs["local"]["relay_backend_public_key"]))
	   replace("cmd/func_test_relay/func_test_relay.go", "const TestRelayBackendPrivateKey = \".*$",  fmt.Sprintf("const TestRelayBackendPrivateKey = \"%s\"", keypairs["local"]["relay_backend_private_key"]))
	}

	fmt.Printf("cmd/func_backend/func_backend.go\n")
	{
	   replace("cmd/func_backend/func_backend.go", "var TestRelayPublicKey =",   fmt.Sprintf("var TestRelayPublicKey = Base64String(\"%s\")", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
	   replace("cmd/func_backend/func_backend.go", "var TestRelayPrivateKey =",   fmt.Sprintf("var TestRelayPrivateKey = Base64String(\"%s\")", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
	   replace("cmd/func_backend/func_backend.go", "var TestRelayBackendPublicKey =",   fmt.Sprintf("var TestRelayBackendPublicKey = Base64String(\"%s\")", keypairs["local"]["relay_backend_public_key"]))
	   replace("cmd/func_backend/func_backend.go", "var TestRelayBackendPrivateKey =",   fmt.Sprintf("var TestRelayBackendPrivateKey = Base64String(\"%s\")", keypairs["local"]["relay_backend_private_key"]))
	   replace("cmd/func_backend/func_backend.go", "var TestServerBackendPublicKey =",   fmt.Sprintf("var TestServerBackendPublicKey = Base64String(\"%s\")", keypairs["local"]["server_backend_public_key"]))
	   replace("cmd/func_backend/func_backend.go", "var TestServerBackendPrivateKey =",   fmt.Sprintf("var TestServerBackendPrivateKey = Base64String(\"%s\")", keypairs["local"]["server_backend_private_key"]))
	}

	fmt.Printf("cmd/func_test_backend/func_test_backend.go\n")
	{
	   replace("cmd/func_test_backend/func_test_backend.go", "const TestRelayPublicKey = \".*$",   fmt.Sprintf("const TestRelayPublicKey = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPublicKey[:])))
	   replace("cmd/func_test_backend/func_test_backend.go", "const TestRelayPrivateKey = \".*$",  fmt.Sprintf("const TestRelayPrivateKey = \"%s\"", base64.StdEncoding.EncodeToString(testRelayPrivateKey[:])))
	   replace("cmd/func_test_backend/func_test_backend.go", "const TestRelayBackendPublicKey = \".*$",  fmt.Sprintf("const TestRelayBackendPublicKey = \"%s\"", keypairs["local"]["relay_backend_public_key"]))
	   replace("cmd/func_test_backend/func_test_backend.go", "const TestRelayBackendPrivateKey = \".*$",  fmt.Sprintf("const TestRelayBackendPrivateKey = \"%s\"", keypairs["local"]["relay_backend_private_key"]))
	   replace("cmd/func_test_backend/func_test_backend.go", "const TestServerBackendPublicKey = \".*$",  fmt.Sprintf("const TestServerBackendPublicKey = \"%s\"", keypairs["local"]["server_backend_public_key"]))
	   replace("cmd/func_test_backend/func_test_backend.go", "const TestServerBackendPrivateKey = \".*$",  fmt.Sprintf("const TestServerBackendPrivateKey = \"%s\"", keypairs["local"]["server_backend_private_key"]))
	   replace("cmd/func_test_backend/func_test_backend.go", "const TestPingKey = \".*$",  fmt.Sprintf("const TestPingKey = \"%s\"", keypairs["local"]["ping_key"]))
	}

	fmt.Printf("cmd/func_test_terraform/func_test_terraform.go\n")
	{
	   replace("cmd/func_test_terraform/func_test_terraform.go", "^const APIPrivateKey = \".*$",   fmt.Sprintf("const APIPrivateKey = \"%s\"", keypairs["local"]["api_private_key"]))
	   replace("cmd/func_test_terraform/func_test_terraform.go", "^\\s*api_key\\s*=\\s*\".*$", fmt.Sprintf("  api_key  = \"%s\"", keypairs["local"]["admin_api_key"]))
	}

	fmt.Printf("\n------------------------------------------\n\n")

   fmt.Printf("*** KEYGEN COMPLETE ***\n\n")
}

// ------------------------------------------------------------------------------

type Config struct {
	CompanyName          string `json:"company_name"`
	VPNAddress           string `json:"vpn_address"`
	CloudflareZoneId     string `json:"cloudflare_zone_id"`
	CloudflareDomain     string `json:"cloudflare_domain"`
	GoogleBillingAccount string `json:"google_billing_account"`
	GoogleOrgId          string `json:"google_org_id"`
	BuyerName            string `json:"buyer_name"`
	BuyerId              string `json:"buyer_id"`
	SSHKey               string `json:"ssh_key"`
}

func fileExists(filename string) bool {
   info, err := os.Stat(filename)
   if os.IsNotExist(err) {
      return false
   }
   return !info.IsDir()
}

func config(env Environment, regexes []string) {
	
	fmt.Printf("configuring network next:\n\n")	

	// load config.json

	file, err := os.Open("config.json")
	if err != nil {
		fmt.Printf("error: could not load config.json\n\n")
		os.Exit(1)
   }
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("error: could not read config.json\n\n")
		os.Exit(1)
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		fmt.Printf("error: could not parse config.json\n\n")
		os.Exit(1)
	}

	// validate config

	fmt.Printf("    company name = \"%s\"\n", config.CompanyName)

	if result, _ := regexp.MatchString(`^[a-zA-Z_]+$`, config.CompanyName); !result {
		fmt.Printf("\nerror: company name must contain only A-Z, a-z and _ characters\n\n")
		os.Exit(1)
	}

	fmt.Printf("    vpn address = \"%s\"\n", config.VPNAddress)

	if config.VPNAddress == "" {
		fmt.Printf("\nerror: you must supply a VPN address\n\n")
		os.Exit(1)
	}

	fmt.Printf("    cloudflare zone id = \"%s\"\n", config.CloudflareZoneId)

	if config.CloudflareZoneId == "" {
		fmt.Printf("\nerror: you must supply a cloudflare zone id\n\n")
		os.Exit(1)
	}

	fmt.Printf("    cloudflare domain = \"%s\"\n", config.CloudflareDomain)

	if config.CloudflareDomain == "" {
		fmt.Printf("\nerror: you must supply a cloudflare domain\n\n")
		os.Exit(1)
	}

	fmt.Printf("    google billing account = \"%s\"\n", config.GoogleBillingAccount)

	if config.GoogleBillingAccount == "" {
		fmt.Printf("\nerror: you must supply a google billing account\n\n")
		os.Exit(1)
	}

	fmt.Printf("    google org id = \"%s\"\n", config.GoogleOrgId)

	if config.GoogleOrgId == "" {
		fmt.Printf("\nerror: you must supply a google org id\n\n")
		os.Exit(1)
	}

	fmt.Printf("    buyer name = \"%s\"\n", config.BuyerName)

	if config.BuyerName == "" {
		fmt.Printf("\nerror: you must supply a buyer name\n\n")
		os.Exit(1)
	}

	fmt.Printf("    buyer id = \"%s\"\n", config.BuyerId)

	if result, _ := regexp.MatchString(`^[a-zA-Z]+$`, config.BuyerId); !result {
		fmt.Printf("\nerror: buyer id must contain only A-Z, a-z\n\n")
		os.Exit(1)
	}

	fmt.Printf("    ssh key = \"%s\"\n", config.SSHKey)

	if config.SSHKey == "" {
		fmt.Printf("\nerror: you must supply an ssh key\n\n")
		os.Exit(1)
	}

	// check that we have necessary files under ~/secrets

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("\nerror: could not get users home dir: %v\n\n", err)
		os.Exit(1)
	}

	secretsDir := fmt.Sprintf("%s/secrets", homeDir)

	if !fileExists(fmt.Sprintf("%s/terraform-cloudflare.txt", secretsDir)) {
		fmt.Printf("\nerror: missing cloudflare terraform api key at ~/secrets/terraform-cloudflare.txt :(\n\n")
		os.Exit(1)
   }

	if !fileExists(fmt.Sprintf("%s/terraform-akamai.txt", secretsDir)) {
		fmt.Printf("\nerror: missing cloudflare akamai api key at ~/secrets/terraform-akamai.txt :(\n\n")
		os.Exit(1)
   }

	if !fileExists(fmt.Sprintf("%s/maxmind.txt", secretsDir)) {
		fmt.Printf("\nerror: missing maxmind license key at ~/secrets/maxmind.txt :(\n\n")
		os.Exit(1)
   }

   // update config in env files

   envs := []string{"local", "dev", "staging", "prod"}

   fmt.Printf("\n")
	fmt.Printf("------------------------------------------\n")
	fmt.Printf("           updating env files             \n")
	fmt.Printf("------------------------------------------\n\n")

   for i := range envs {
   	envFile := fmt.Sprintf("envs/%s.env", envs[i])
	   fmt.Printf("%s\n", envFile)
	   {
			if envs[i] != "prod" {
				if envs[i] != "local" {
				   replace(envFile, "^\\s*API_URL\\s*=.*$", fmt.Sprintf("API_URL=\"https://api-%s.%s\"", envs[i], config.CloudflareDomain))
				   replace(envFile, "^\\s*RELAY_BACKEND_URL\\s*=.*$", fmt.Sprintf("RELAY_BACKEND_URL=\"https://relay-%s.%s\"", envs[i], config.CloudflareDomain))
				   replace(envFile, "^\\s*RASPBERRY_BACKEND_URL\\s*=.*$", fmt.Sprintf("NEXT_RASPBERRY_BACKEND_URL=\"https://raspberry-%s.%s\"", envs[i], config.CloudflareDomain))
				   replace(envFile, "^\\s*NEXT_SERVER_BACKEND_HOSTNAME\\s*=.*$", fmt.Sprintf("NEXT_SERVER_BACKEND_HOSTNAME=\"server-%s.%s\"", envs[i], config.CloudflareDomain))
				}
			} else {
			   replace(envFile, "^\\s*API_URL\\s*=.*$", fmt.Sprintf("API_URL=\"https://api.%s\"", config.CloudflareDomain))
			   replace(envFile, "^\\s*NEXT_SERVER_BACKEND_HOSTNAME\\s*=.*$", fmt.Sprintf("NEXT_SERVER_BACKEND_HOSTNAME=\"server.%s\"", config.CloudflareDomain))
			   replace(envFile, "^\\s*RELAY_BACKEND_URL\\s*=.*$", fmt.Sprintf("RELAY_BACKEND_URL=\"https://relay.%s\"", config.CloudflareDomain))
			   replace(envFile, "^\\s*RASPBERRY_BACKEND_URL\\s*=.*$", fmt.Sprintf("NEXT_RASPBERRY_BACKEND_URL=\"https://raspberry.%s\"", config.CloudflareDomain))
			}
		   replace(envFile, "^\\s*VPN_ADDRESS\\s*=.*$", fmt.Sprintf("VPN_ADDRESS=\"%s\"", config.VPNAddress))
		   replace(envFile, "^\\s*SSH_KEY_FILE\\s*=.*$", fmt.Sprintf("SSH_KEY_FILE=\"~/.ssh/%s\"", config.SSHKey))
		   replace(envFile, "^\\s*RELAY_ARTIFACTS_BUCKET_NAME\\s*=.*$", fmt.Sprintf("RELAY_ARTIFACTS_BUCKET_NAME=\"%s\"", fmt.Sprintf("%s_network_next_relay_artifacts", config.CompanyName)))
		   replace(envFile, "^\\s*IP2LOCATION_BUCKET_NAME\\s*=.*$", fmt.Sprintf("IP2LOCATION_BUCKET_NAME=\"%s\"", fmt.Sprintf("%s_network_next_%s", config.CompanyName, envs[i])))
		}
   }

   // update config in terraform files

	fmt.Printf("\n------------------------------------------\n        updating terraform files\n------------------------------------------\n\n")

   for i := range envs {

   	filenames := []string {
   		fmt.Sprintf("terraform/%s/backend/main.tf", envs[i]),
   		fmt.Sprintf("terraform/%s/relays/main.tf", envs[i]),
   	}

   	for j := range filenames {
   		if fileExists(filenames[j]) {
	   		fmt.Printf("%s\n", filenames[j])
			   replace(filenames[j], "^\\s*bucket\\s*=\\s*\"[a-zA-Z_]+\"\\s*$", fmt.Sprintf("    bucket  = \"%s_network_next_terraform\"", config.CompanyName))
   		}
   	}

   	filenames = []string {
   		fmt.Sprintf("terraform/%s/backend/terraform.tfvars", envs[i]),
   		fmt.Sprintf("terraform/%s/relays/terraform.tfvars", envs[i]),
     	}

   	for j := range filenames {
   		if fileExists(filenames[j]) {
	   		fmt.Printf("%s\n", filenames[j])
			   replace(filenames[j], "^\\s*google_artifacts_bucket\\s*=.*$", fmt.Sprintf("google_artifacts_bucket     = \"gs://%s_network_next_backend_artifacts\"", config.CompanyName))
			   replace(filenames[j], "^\\s*google_database_bucket\\s*=.*$",  fmt.Sprintf("google_database_bucket      = \"gs://%s_network_next_database_files\"", config.CompanyName))
			   replace(filenames[j], "^\\s*cloudflare_domain\\s*=.*$",       fmt.Sprintf("cloudflare_domain           = \"%s\"", config.CloudflareDomain))
			   replace(filenames[j], "^\\s*ip2location_bucket_name\\s*=.*$", fmt.Sprintf("ip2location_bucket_name     = \"%s_network_next_%s\"", config.CompanyName, envs[i]))
			   replace(filenames[j], "^\\s*ssh_public_key_file\\s*=.*$",     fmt.Sprintf("ssh_public_key_file         = \"~/.ssh/%s.pub\"", config.SSHKey))
			   replace(filenames[j], "^\\s*ssh_private_key_file\\s*=.*$",    fmt.Sprintf("ssh_private_key_file        = \"~/.ssh/%s\"", config.SSHKey))
			   replace(filenames[j], "^\\s*relay_artifacts_bucket\\s*=.*$",  fmt.Sprintf("relay_artifacts_bucket      = \"%s_network_next_relay_artifacts\"", config.CompanyName))
			   if envs[i] != "prod" {
				   replace(filenames[j], "^\\s*relay_backend_url\\s*=.*$",    fmt.Sprintf("relay_backend_url           = \"relay-%s.%s\"", envs[i], config.CloudflareDomain))
  			   } else {
				   replace(filenames[j], "^\\s*relay_backend_url\\s*=.*$",    fmt.Sprintf("relay_backend_url           = \"relay.%s\"", config.CloudflareDomain))			   	
			   }
   		}
   	}

   	filenames = []string {
   		fmt.Sprintf("terraform/%s/relays/main.tf", envs[i]),
   	}

   	for j := range filenames {
   		if fileExists(filenames[j]) {
	   		fmt.Printf("%s\n", filenames[j])
			   if envs[i] != "prod" {
				   replace(filenames[j], "^\\s*hostname\\s*=.*$",             fmt.Sprintf("  hostname = \"https://api-%s.%s\"", envs[i], config.CloudflareDomain))
  			   } else {
				   replace(filenames[j], "^\\s*hostname\\s*=.*$",             fmt.Sprintf("  hostname = \"https://api.%s\"", config.CloudflareDomain))
			   }
			   replace(filenames[j], "^\\s*ssh_public_key_file\\s*=.*$",     fmt.Sprintf("  ssh_public_key_file = \"~/.ssh/%s.pub\"", config.SSHKey))
   		}
   	}
   }

	fmt.Printf("terraform/projects/main.tf\n")
	{
   	replace("terraform/projects/main.tf", "^\\s*org_id = \"\\d+\"\\s*$", fmt.Sprintf("  org_id = \"%s\"", config.GoogleOrgId))
   	replace("terraform/projects/main.tf", "^\\s*billing_account = \"[A-Za-z0-9-]+\"\\s*$", fmt.Sprintf("  billing_account = \"%s\"", config.GoogleBillingAccount))
   	replace("terraform/projects/main.tf", "^\\s*company_name = \"[A-Za-z0-9-]+\"\\s*$", fmt.Sprintf("  company_name = \"%s\"", config.CompanyName))
	}

	// update source files

	fmt.Printf("\n------------------------------------------\n         updating source files\n------------------------------------------\n\n")

	fmt.Printf("sdk/include/next_config.h\n")
   {
   	replace("sdk/include/next_config.h", "^\\s*\\#define NEXT_PROD_SERVER_BACKEND_HOSTNAME.*$", fmt.Sprintf("#define NEXT_PROD_SERVER_BACKEND_HOSTNAME \"server.%s\"", config.CloudflareDomain))
   	replace("sdk/include/next_config.h", "^\\s*\\#define NEXT_DEV_SERVER_BACKEND_HOSTNAME.*$", fmt.Sprintf("#define NEXT_DEV_SERVER_BACKEND_HOSTNAME \"server-dev.%s\"", config.CloudflareDomain))
   	replace("sdk/include/next_config.h", "^\\s*\\#define NEXT_CONFIG_BUCKET_NAME\\s+\"[A-Za-z_]+?_network_next_sdk_config\"\\s*$", fmt.Sprintf("#define NEXT_CONFIG_BUCKET_NAME \"%s_network_next_sdk_config\"", config.CompanyName))
   }

	fmt.Printf("sdk/examples/upgraded_server.cpp\n")
	{
   	replace("sdk/examples/upgraded_server.cpp", "^\\s*const char \\* server_backend_hostname = \"server-dev\\..+\";\\s*$", fmt.Sprintf("const char * server_backend_hostname = \"server-dev.%s\";", config.CloudflareDomain))
	}

	fmt.Printf("sdk/examples/complex_server.cpp\n")
	{
   	replace("sdk/examples/complex_server.cpp", "^\\s*const char \\* server_backend_hostname = \"server-dev\\..+\";\\s*$", fmt.Sprintf("const char * server_backend_hostname = \"server-dev.%s\";", config.CloudflareDomain))
	}

   // update semaphore ci files

	fmt.Printf("\n------------------------------------------\n        updating semaphore files\n------------------------------------------\n\n")

   fmt.Printf(".semaphore/upload-artifacts.yml\n")
   {
   	replace(".semaphore/upload-artifacts.yml", "^\\s*- export ARTIFACT_BUCKET=gs://[a-zA-Z_]+?_network_next_backend_artifacts\\s*$", fmt.Sprintf("            - export ARTIFACT_BUCKET=gs://%s_network_next_backend_artifacts", config.CompanyName))
   }

	fmt.Printf(".semaphore/upload-relay.yml\n")
	{
		replace(".semaphore/upload-relay.yml", "^\\s*-\\s*export RELAY_BUCKET=gs://[a-zA-Z_]+?_network_next_relay_artifacts\\s*$",       fmt.Sprintf("            - export RELAY_BUCKET=gs://%s_network_next_relay_artifacts", config.CompanyName))
	}

	fmt.Printf(".semaphore/upload-config.yml\n")
	{
   	replace(".semaphore/upload-config.yml", "^\\s*- export SDK_CONFIG_BUCKET=gs://[a-zA-Z_]+?_network_next_sdk_config\\s*$",         fmt.Sprintf("            - export SDK_CONFIG_BUCKET=gs://%s_network_next_sdk_config", config.CompanyName))
	}

   // update config in portal .env files

	fmt.Printf("\n------------------------------------------\n      updating portal .env files\n------------------------------------------\n\n")

	for i := range envs {
		filename := fmt.Sprintf("portal/.env.%s", envs[i])
		if fileExists(filename) {
			fmt.Printf("%s\n", filename)
			if envs[i] != "prod" {
		   	replace(filename, "^VUE_APP_API_URL=.*$", fmt.Sprintf("VUE_APP_API_URL=https://api-%s.%s", envs[i], config.CloudflareDomain))
			} else {
		   	replace(filename, "^VUE_APP_API_URL=.*$", fmt.Sprintf("VUE_APP_API_URL=https://api.%s", config.CloudflareDomain))
			}
		}
	}

   // configure amazon

   fmt.Printf("\n--------------------------------------------\n                   amazon\n--------------------------------------------\n")

   if !bash("run config-amazon") {
		fmt.Printf("\nerror: failed to configure amazon :(\n\n")
		os.Exit(1)
   }

   // configure akamai

   fmt.Printf("--------------------------------------------\n                   akamai\n--------------------------------------------\n")

   if !bash("run config-akamai") {
		fmt.Printf("\nerror: failed to configure akamai :(\n\n")
		os.Exit(1)
   }

   // configure google

   fmt.Printf("--------------------------------------------\n                   google\n--------------------------------------------\n")

   if !bash("run config-google") {
		fmt.Printf("\nerror: failed to configure google :(\n\n")
		os.Exit(1)
   }

   // generate staging.sql

   fmt.Printf("--------------------------------------------\n")
	fmt.Printf("           Generating staging.sql           \n")
	fmt.Printf("--------------------------------------------\n\n")

   ok := bash("run generate-staging-sql > /dev/null")
   if !ok {
   	fmt.Printf("\nerror: could not generate staging.sql\n\n")
   	os.Exit(1)
   }

   bash("cat schemas/sql/staging.sql")

   fmt.Printf("\n")

   // generate empty.bin

   fmt.Printf("--------------------------------------------\n")
	fmt.Printf("           Generating empty.bin             \n")
	fmt.Printf("--------------------------------------------\n\n")
   {
	   ok = bash("run sql-destroy && run sql-create && run extract-database && mv database.bin envs/empty.bin")
	   if !ok {
	   	fmt.Printf("\nerror: could not generate empty.bin\n\n")
	   	os.Exit(1)
	   }
   }

   // generate local.bin

   fmt.Printf("--------------------------------------------\n")
	fmt.Printf("           Generating local.bin             \n")
	fmt.Printf("--------------------------------------------\n\n")
   {
	   ok = bash("run sql-destroy && run sql-create && run sql-local && run extract-database && mv database.bin envs/local.bin")
	   if !ok {
	   	fmt.Printf("\nerror: could not generate local.bin\n\n")
	   	os.Exit(1)
	   }
   }

   // generate docker.bin

   fmt.Printf("--------------------------------------------\n")
	fmt.Printf("           Generating docker.bin            \n")
	fmt.Printf("--------------------------------------------\n\n")
   {
	   ok = bash("run sql-destroy && run sql-create && run sql-docker && run extract-database && mv database.bin envs/docker.bin")
	   if !ok {
	   	fmt.Printf("\nerror: could not generate docker.bin\n\n")
	   	os.Exit(1)
	   }
   }

   // generate staging.bin

   fmt.Printf("--------------------------------------------\n")
	fmt.Printf("           Generating staging.bin           \n")
	fmt.Printf("--------------------------------------------\n\n")
   {
	   ok = bash("run sql-destroy && run sql-create && run sql-staging && run extract-database && mv database.bin envs/staging.bin")
	   if !ok {
	   	fmt.Printf("\nerror: could not generate staging.bin\n\n")
	   	os.Exit(1)
	   }
   }

   fmt.Printf("--------------------------------------------\n\n")

   fmt.Printf("*** CONFIGURATION COMPLETE ***\n\n")
}

// -------------------------------------------------------------------------------------------------------

func secrets() {

	// zip up all secrets so we can upload them to semaphore ci in a single artifact

	fmt.Printf("copying secrets from terraform/projects to ~/secrets...\n")

	bash("cp -f terraform/projects/*.json ~/secrets")

	fmt.Printf("\nzipping up secrets -> secrets.tar.gz\n\n")

   if !bash("cd ~/secrets && rm -f secrets.tar.gz && tar -czvf secrets.tar.gz . 2> /dev/null") {
		fmt.Printf("\nerror: failed to tar gzip secrets :(\n\n")
		os.Exit(1)
   }

   bash("mv -f ~/secrets/secrets.tar.gz .")

   fmt.Printf("secrets.tar.gz is ready\n\n")
}

// -------------------------------------------------------------------------------------------------------

func GetJSON(apiKey string, url string, object interface{}) {

	var err error
	var response *http.Response
	for i := 0; i < 30; i++ {
		req, err := http.NewRequest("GET", url, bytes.NewBuffer(nil))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		client := &http.Client{}
		response, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}

	if err != nil {
		panic(fmt.Sprintf("failed to read %s: %v", url, err))
	}

	if response == nil {
		core.Error("no response for %s", url)
		fmt.Printf("\n")
		os.Exit(1)
	}

	if response.Body == nil {
		core.Error("no response body for %s", url)
		fmt.Printf("\n")
		os.Exit(1)
	}

	body, error := io.ReadAll(response.Body)
	if error != nil {
		panic(fmt.Sprintf("could not read response body for %s: %v", url, err))
	}

	response.Body.Close()

	err = json.Unmarshal([]byte(body), &object)
	if err != nil {
		panic(fmt.Sprintf("could not parse json response for %s: %v", url, err))
	}
}

func GetText(apiKey string, url string) string {

	var err error
	var response *http.Response
	for i := 0; i < 30; i++ {
		req, err := http.NewRequest("GET", url, bytes.NewBuffer(nil))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		client := &http.Client{}
		response, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}

	if err != nil {
		panic(fmt.Sprintf("failed to read %s: %v", url, err))
	}

	if response == nil {
		core.Error("no response from %s", url)
		os.Exit(1)
	}

	if response.StatusCode != 200 {
		panic(fmt.Sprintf("got %d response for %s", response.StatusCode, url))
	}

	body, error := io.ReadAll(response.Body)
	if error != nil {
		panic(fmt.Sprintf("could not read response body for %s: %v", url, err))
	}

	response.Body.Close()

	return string(body)
}

func GetBinary(apiKey string, url string) []byte {

	var err error
	var response *http.Response
	for i := 0; i < 30; i++ {
		req, err := http.NewRequest("GET", url, bytes.NewBuffer(nil))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		client := &http.Client{}
		response, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}

	if err != nil {
		panic(fmt.Sprintf("failed to read %s: %v", url, err))
	}

	if response == nil {
		core.Error("no response from %s", url)
		os.Exit(1)
	}

	if response.StatusCode != 200 {
		panic(fmt.Sprintf("got %d response for %s", response.StatusCode, url))
	}

	body, error := io.ReadAll(response.Body)
	if error != nil {
		panic(fmt.Sprintf("could not read response body for %s: %v", url, err))
	}

	response.Body.Close()

	return body
}

func PutJSON(apiKey string, url string, requestData interface{}, responseData interface{}) error {

	buffer := new(bytes.Buffer)

	json.NewEncoder(buffer).Encode(requestData)

	request, _ := http.NewRequest("PUT", url, buffer)

	request.Header.Set("Authorization", "Bearer "+apiKey)

	httpClient := &http.Client{}

	var err error
	var response *http.Response
	for i := 0; i < 5; i++ {
		response, err = httpClient.Do(request)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}

	if err != nil {
		return fmt.Errorf("failed to read %s: %v", url, err)
	}

	if response == nil {
		return fmt.Errorf("no response from %s", url)
	}

	body, error := io.ReadAll(response.Body)
	if error != nil {
		return fmt.Errorf("could not read response body for %s: %v", url, err)
	}

	response.Body.Close()

	err = json.Unmarshal([]byte(body), &responseData)
	if err != nil {
		return fmt.Errorf("could not parse json response for %s: %v", url, err)
	}

	return nil
}

// -------------------------------------------------------------------------------------------------------

var cachedDatabase *db.Database

type AdminDatabaseResponse struct {
	Database string `json:"database_base64"`
	Error    string `json:"error"`
}

func getAdminAPIKey() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("error: could not get users home dir: %v\n\n", err)
		os.Exit(1)
	}
	filename := fmt.Sprintf("%s/secrets/%s-admin-api-key.txt", homeDir, env.Name)
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("error: could not read admin api key from secrets dir: %v\n\n", err)
		os.Exit(1)
	}
	return string(data)
}

func getDatabase() *db.Database {

	if cachedDatabase != nil {
		return cachedDatabase
	}

	if env.Name != "local" {

		response := AdminDatabaseResponse{}
		GetJSON(getAdminAPIKey(), fmt.Sprintf("%s/admin/database", env.API_URL), &response)
		if response.Error != "" {
			fmt.Printf("%s\n", response.Error)
			os.Exit(1)
		}
		database_binary, err := base64.StdEncoding.DecodeString(response.Database)
		if err != nil {
			fmt.Printf("error: could not decode base64 database string\n")
			os.Exit(1)
		}
		os.WriteFile("database.bin", database_binary, 0644)
	}

	cachedDatabase, err := db.LoadDatabase("database.bin")
	if err != nil {
		fmt.Printf("error: could not load database.bin: %v\n", err)
		os.Exit(1)
		return nil
	}

	return cachedDatabase
}

func printDatabase() {
	fmt.Printf("downloading database.bin from Postgres SQL instance\n\n")
	database := getDatabase()
	fmt.Println(database.String())
	fmt.Printf("\n")
}

type AdminCommitRequest struct {
	User     string `json:"user"`
	Database string `json:"database_base64"`
}

type AdminCommitResponse struct {
	Error string `json:"error"`
}

func commitDatabase() {

	bash("rm database.bin")

	getDatabase()

	database, err := db.LoadDatabase("database.bin")
	if err != nil {
		fmt.Printf("error: could not load database.bin")
		os.Exit(1)
	}

	gitUser := bashQuiet("git config user.name")
	gitEmail := bashQuiet("git config user.email")
	gitUser = strings.ReplaceAll(gitUser, "\n", "")
	gitEmail = strings.ReplaceAll(gitEmail, "\n", "")

	database_binary := database.GetBinary()

	database_base64 := base64.StdEncoding.EncodeToString(database_binary)

	var request AdminCommitRequest
	var response AdminCommitResponse

	request.User = fmt.Sprintf("%s <%s>", gitUser, gitEmail)
	request.Database = database_base64

	err = PutJSON(getAdminAPIKey(), fmt.Sprintf("%s/admin/commit", env.API_URL), &request, &response)
	if err != nil {
		fmt.Printf("error: could not post JSON to commit database endpoint: %v", err)
		os.Exit(1)
	}

	if response.Error != "" {
		fmt.Printf("error: failed to commit database: %s\n\n", response.Error)
		os.Exit(1)
	}

	fmt.Printf("successfully committed database to %s\n\n", env.Name)
}

type PortalRelayData struct {
	RelayName    string `json:"relay_name"`
	RelayId      string `json:"relay_id"`
	RelayAddress string `json:"relay_address"`
	NumSessions  uint32 `json:"num_sessions"`
	MaxSessions  uint32 `json:"max_sessions"`
	StartTime    string `json:"start_time"`
	RelayFlags   string `json:"relay_flags"`
	RelayVersion string `json:"relay_version"`
	Uptime       string `json:"uptime"`
}

type PortalRelaysResponse struct {
	Relays []PortalRelayData `json:"relays"`
}

type AdminRelaysResponse struct {
	Relays []admin.RelayData `json:"relays"`
	Error  string            `json:"error"`
}

func niceUptime(uptimeString string) string {
	value, _ := strconv.ParseInt(uptimeString, 10, 64)
	if value > 86400 {
		return fmt.Sprintf("%dd", int(math.Floor(float64(value/86400))))
	}
	if value > 3600 {
		return fmt.Sprintf("%dh", int(math.Floor(float64(value/3600))))
	}
	if value > 60 {
		return fmt.Sprintf("%dm", int(math.Floor(float64(value/60))))
	}
	return fmt.Sprintf("%ds", value)
}

func printRelays(env Environment, relayCount int64, alphaSort bool, regexName string) {

	adminRelaysResponse := AdminRelaysResponse{}
	portalRelaysResponse := PortalRelaysResponse{}

	GetJSON(getAdminAPIKey(), fmt.Sprintf("%s/admin/relays", env.API_URL), &adminRelaysResponse)
	GetJSON(getAdminAPIKey(), fmt.Sprintf("%s/portal/all_relays", env.API_URL), &portalRelaysResponse)

	type RelayRow struct {
		Name            string
		PublicAddress   string
		InternalAddress string
		InternalGroup   string
		Id              string
		Status          string
		Sessions        int
		Uptime          string
		Version         string
	}

	relayMap := make(map[string]*RelayRow)

	for i := range adminRelaysResponse.Relays {
		relayAddress := fmt.Sprintf("%s:%d", adminRelaysResponse.Relays[i].PublicIP, adminRelaysResponse.Relays[i].PublicPort)
		relay := relayMap[relayAddress]
		if relay == nil {
			relay = &RelayRow{}
			relayMap[relayAddress] = relay
		}
		relay.Name = adminRelaysResponse.Relays[i].RelayName
		relay.Id = fmt.Sprintf("%x", common.HashString(relayAddress))
		relay.PublicAddress = relayAddress
		if adminRelaysResponse.Relays[i].InternalIP != "0.0.0.0" {
			relay.InternalAddress = fmt.Sprintf("%s:%d", adminRelaysResponse.Relays[i].InternalIP, adminRelaysResponse.Relays[i].InternalPort)
		}
		relay.InternalGroup = adminRelaysResponse.Relays[i].InternalGroup
		relay.Status = "offline"
		relay.Sessions = 0
		relay.Version = adminRelaysResponse.Relays[i].Version
	}

	for i := range portalRelaysResponse.Relays {
		relayAddress := portalRelaysResponse.Relays[i].RelayAddress
		relay := relayMap[relayAddress]
		if relay == nil {
			continue
		}
		relayFlags, _ := strconv.ParseUint(portalRelaysResponse.Relays[i].RelayFlags, 16, 64)
		if (relayFlags & constants.RelayFlags_ShuttingDown) != 0 {
			relay.Status = "shutting down"
		} else {
			relay.Status = "online"
		}
		relay.Sessions = int(portalRelaysResponse.Relays[i].NumSessions)
		if portalRelaysResponse.Relays[i].RelayVersion != "" {
			relay.Version = portalRelaysResponse.Relays[i].RelayVersion
		}
		relay.Uptime = niceUptime(portalRelaysResponse.Relays[i].Uptime)
	}

	relays := make([]RelayRow, len(relayMap))
	index := 0
	for _, v := range relayMap {
		relays[index] = *v
		index++
	}

	filtered := []RelayRow{}

	for _, relay := range relays {
		if match, err := regexp.Match(regexName, []byte(relay.Name)); match && err == nil {
			filtered = append(filtered, relay)
			continue
		}
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].Name < filtered[j].Name
	})

	if !alphaSort {
		sort.SliceStable(filtered, func(i, j int) bool {
			return filtered[i].Sessions > filtered[j].Sessions
		})
	}

	outputRelays := filtered

	for i := range outputRelays {
		if outputRelays[i].Sessions < 0 {
			outputRelays[i].Sessions = 0
		}
	}

	if relayCount != 0 && int(relayCount) < len(outputRelays) {
		outputRelays = outputRelays[0:relayCount]
	}

	if len(outputRelays) > 0 {
		table.Output(outputRelays)
		fmt.Printf("\n")
	} else {
		fmt.Printf("no relays found\n\n")
	}
}

// ----------------------------------------------------------------

type SSHConn struct {
	user    string
	address string
	port    string
	keyfile string
}

func NewSSHConn(user, address string, port string, authKeyFilename string) SSHConn {
	return SSHConn{
		user:    user,
		address: address,
		port:    port,
		keyfile: authKeyFilename,
	}
}

func (con SSHConn) commonSSHCommands() []string {
	args := make([]string, 6)
	args[0] = "-i"
	args[1] = con.keyfile
	args[2] = "-p"
	args[3] = con.port
	args[4] = "-o"
	args[5] = "StrictHostKeyChecking=no"
	return args
}

func (con SSHConn) Connect() {
	args := con.commonSSHCommands()
	args = append(args, "-tt", con.user+"@"+con.address)
	runCommandEnv("ssh", args, nil)
}

func (con SSHConn) ConnectAndIssueCmd(cmd string) bool {
	args := con.commonSSHCommands()
	args = append(args, "-tt", con.user+"@"+con.address, "--", cmd)
	runCommandEnv("ssh", args, nil)
	return true
}

// ------------------------------------------------------------------------------

const (
	SetupRelayScript = `

# run once only

if [[ -f /etc/relay_setup_completed ]]; then echo "already setup" && exit 0; fi

# make the relay prompt cool

echo making the relay prompt cool

sudo echo "export PS1=\"\[\033[36m\]$RELAY_NAME [$ENVIRONMENT] \[\033[00m\]\w # \"" >> ~/.bashrc
sudo echo "source ~/.bashrc" >> ~/.profile.sh

# download the relay binary and rename it to 'relay'

echo downloading relay binary

rm -f $RELAY_VERSION

wget https://storage.googleapis.com/$RELAY_ARTIFACTS_BUCKET_NAME/$RELAY_VERSION --no-cache

if [ ! $? -eq 0 ]; then
    echo "download relay binary failed"
    exit 1
fi

sudo mv $RELAY_VERSION relay

sudo chmod +x relay

# setup the relay environment file

echo setting up relay environment

sudo cat > relay.env <<- EOM
RELAY_NAME=$RELAY_NAME
RELAY_NUM_THREADS=1
RELAY_PUBLIC_ADDRESS=$RELAY_PUBLIC_ADDRESS
RELAY_INTERNAL_ADDRESS=$RELAY_INTERNAL_ADDRESS
RELAY_PUBLIC_KEY=$RELAY_PUBLIC_KEY
RELAY_PRIVATE_KEY=$RELAY_PRIVATE_KEY
RELAY_BACKEND_URL=$RELAY_BACKEND_URL
RELAY_BACKEND_PUBLIC_KEY=$RELAY_BACKEND_PUBLIC_KEY
EOM

# setup the relay service file

echo setting up relay service file

sudo cat > relay.service <<- EOM
[Unit]
Description=Network Next Relay
ConditionPathExists=/app/relay
After=network.target

[Service]
Type=simple
LimitNOFILE=1024
WorkingDirectory=/app
ExecStart=/app/relay
EnvironmentFile=/app/relay.env
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOM

# move everything into the /app dir

echo moving everything into /app

sudo rm -rf /app
sudo mkdir /app
sudo mv relay /app/relay
sudo mv relay.env /app/relay.env
sudo mv relay.service /app/relay.service

# limit maximum journalctl logs to 200MB so we don't run out of disk space

echo limiting max journalctl logs to 200MB

sudo sed -i "s/\(.*SystemMaxUse= *\).*/\SystemMaxUse=200M/" /etc/systemd/journald.conf
sudo systemctl restart systemd-journald

# install the relay service, then start it and watch the logs

echo installing relay service

sudo systemctl enable /app/relay.service

echo starting relay service

sudo systemctl start relay

sudo touch /etc/relay_setup_completed

echo setup completed
`

	StartRelayScript = `sudo systemctl enable /app/relay.service && sudo systemctl start relay`

	StopRelayScript = `sudo systemctl stop relay && sudo systemctl disable relay`

	LoadRelayScript = `( sudo systemctl stop relay || true ) && sudo journalctl --vacuum-size 10M && rm -rf relay && wget https://storage.googleapis.com/%s/%s -O relay --no-cache && chmod +x relay && ./relay version && sudo mv relay /app/relay && sudo systemctl start relay && exit`

	UpgradeRelayScript = `sudo journalctl --vacuum-size 10M && sudo systemctl stop relay; sudo apt update -y && sudo apt upgrade -y && sudo apt dist-upgrade -y && sudo apt autoremove -y && sudo reboot`

	RebootRelayScript = `sudo reboot`

	ConfigRelayScript = `sudo vi /app/relay.env && exit`
)

func getRelayInfo(env Environment, regex string) []admin.RelayData {

	relaysResponse := AdminRelaysResponse{}

	GetJSON(getAdminAPIKey(), fmt.Sprintf("%s/admin/relays", env.API_URL), &relaysResponse)

	relays := make([]admin.RelayData, 0)

	for i := range relaysResponse.Relays {
		matched, _ := regexp.Match(regex, []byte(relaysResponse.Relays[i].RelayName))
		if !matched {
			continue
		}
		relays = append(relays, relaysResponse.Relays[i])
	}

	return relays
}

func ssh(env Environment, regexes []string) {

	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		if len(relays) == 0 {
			fmt.Printf("no relays matched the regex '%s'\n", regex)
			continue
		}
		for i := range relays {
			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("%s does not have an SSH address\n", relays[i].RelayName)
				continue
			}
			fmt.Printf("connecting to %s\n", relays[i].RelayName)
			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)
			con.Connect()
			break
		}
	}

	fmt.Printf("\n")
}

func setupRelays(env Environment, regexes []string) {
	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		if len(relays) == 0 {
			fmt.Printf("no relays matched the regex '%s'\n", regex)
			continue
		}
		for i := range relays {

			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("relay %s does not have an SSH address :(\n", relays[i].RelayName)
				continue
			}

			fmt.Printf("setting up relay %s\n", relays[i].RelayName)

			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)

			script := SetupRelayScript

			relayName := relays[i].RelayName
			relayVersion := relays[i].Version
			relayPublicAddress := fmt.Sprintf("%s:%d", relays[i].PublicIP, relays[i].PublicPort)
			relayInternalAddress := fmt.Sprintf("%s:%d", relays[i].InternalIP, relays[i].InternalPort)
			relayPublicKeyBase64 := relays[i].PublicKeyBase64
			relayPrivateKeyBase64 := relays[i].PrivateKeyBase64
			relayBackendURL := env.RelayBackendURL
			relayBackendPublicKeyBase64 := env.RelayBackendPublicKey
			vpnAddress := env.VPNAddress
			relayArtifactsBucketName := env.RelayArtifactsBucketName

			environment := env.Name

			script = strings.ReplaceAll(script, "$RELAY_NAME", relayName)
			script = strings.ReplaceAll(script, "$RELAY_VERSION", relayVersion)
			script = strings.ReplaceAll(script, "$RELAY_PUBLIC_ADDRESS", relayPublicAddress)
			script = strings.ReplaceAll(script, "$RELAY_INTERNAL_ADDRESS", relayInternalAddress)
			script = strings.ReplaceAll(script, "$RELAY_PUBLIC_KEY", relayPublicKeyBase64)
			script = strings.ReplaceAll(script, "$RELAY_PRIVATE_KEY", relayPrivateKeyBase64)
			script = strings.ReplaceAll(script, "$RELAY_BACKEND_URL", relayBackendURL)
			script = strings.ReplaceAll(script, "$RELAY_BACKEND_PUBLIC_KEY", relayBackendPublicKeyBase64)
			script = strings.ReplaceAll(script, "$VPN_ADDRESS", vpnAddress)
			script = strings.ReplaceAll(script, "$ENVIRONMENT", environment)
			script = strings.ReplaceAll(script, "$RELAY_ARTIFACTS_BUCKET_NAME", relayArtifactsBucketName)

			con.ConnectAndIssueCmd(script)

			if len(relays) > 1 {
				fmt.Printf("\n----------------------------------------------\n\n")
			}
		}
	}
	fmt.Printf("\n")
}

func startRelays(env Environment, regexes []string) {
	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		if len(relays) == 0 {
			fmt.Printf("no relays matched the regex '%s'\n", regex)
			continue
		}
		for i := range relays {
			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("relay %s does not have an SSH address :(\n", relays[i].RelayName)
				continue
			}
			fmt.Printf("starting relay %s\n", relays[i].RelayName)
			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)
			con.ConnectAndIssueCmd(StartRelayScript)
		}
	}
}

func stopRelays(env Environment, regexes []string) {
	script := StopRelayScript
	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		if len(relays) == 0 {
			fmt.Printf("no relays matched the regex '%s'\n", regex)
			continue
		}
		for i := range relays {
			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("relay %s does not have an SSH address :(\n", relays[i].RelayName)
				continue
			}
			fmt.Printf("stopping relay %s\n", relays[i].RelayName)
			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)
			con.ConnectAndIssueCmd(script)
		}
	}
}

func upgradeRelays(env Environment, regexes []string) {
	script := UpgradeRelayScript
	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		if len(relays) == 0 {
			fmt.Printf("no relays matched the regex '%s'\n", regex)
			continue
		}
		for i := range relays {
			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("relay %s does not have an SSH address :(\n", relays[i].RelayName)
				continue
			}
			fmt.Printf("upgrading relay %s\n", relays[i].RelayName)
			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)
			con.ConnectAndIssueCmd(script)
		}
	}
}

func rebootRelays(env Environment, regexes []string) {
	script := RebootRelayScript
	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		if len(relays) == 0 {
			fmt.Printf("no relays matched the regex '%s'\n", regex)
			continue
		}
		for i := range relays {
			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("relay %s does not have an SSH address :(\n", relays[i].RelayName)
				continue
			}
			fmt.Printf("rebooting relay %s\n", relays[i].RelayName)
			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)
			con.ConnectAndIssueCmd(script)
		}
	}
}

func loadRelays(env Environment, regexes []string, version string) {
	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		if len(relays) == 0 {
			fmt.Printf("no relays matched the regex '%s'\n", regex)
			continue
		}
		for i := range relays {
			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("relay %s does not have an SSH address :(\n", relays[i].RelayName)
				continue
			}
			fmt.Printf("loading %s onto %s\n", version, relays[i].RelayName)
			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)
			con.ConnectAndIssueCmd(fmt.Sprintf(LoadRelayScript, env.RelayArtifactsBucketName, version))
		}
	}
}

func relayLog(env Environment, regexes []string) {
	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		for i := range relays {
			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("Relay %s does not have an SSH address :(\n", relays[i].RelayName)
				continue
			}
			fmt.Printf("connecting to %s\n", relays[i].RelayName)
			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)
			con.ConnectAndIssueCmd("journalctl -fu relay -n 1000")
			break
		}
	}
}

func keys(env Environment, regexes []string) {
	for _, regex := range regexes {
		relays := getRelayInfo(env, regex)
		for i := range relays {
			if relays[i].SSH_IP == "0.0.0.0" {
				fmt.Printf("Relay %s does not have an SSH address :(\n", relays[i].RelayName)
				continue
			}
			fmt.Printf("connecting to %s\n", relays[i].RelayName)
			con := NewSSHConn(relays[i].SSH_User, relays[i].SSH_IP, fmt.Sprintf("%d", relays[i].SSH_Port), env.SSHKeyFile)
			con.ConnectAndIssueCmd("sudo cat /app/relay.env | grep _KEY")
			break
		}
	}
}

// --------------------------------------------------------------------------------------------

type Environment struct {
	Name                     string `json:"name"`
	API_URL                  string `json:"api_url"`
	PortalAPIKey             string `json:"portal_api_key"`
	VPNAddress               string `json:"vpn_address"`
	SSHKeyFile               string `json:"ssh_key_file"`
	RelayBackendURL          string `json:"relay_backend_url"`
	RelayBackendPublicKey    string `json:"relay_backend_public_key"`
	RelayArtifactsBucketName string `json:"relay_artifacts_bucket_name"`
	RaspberryBackendURL      string `json:"raspberry_backend_url"`
}

func (e *Environment) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s]\n\n", e.Name))
	sb.WriteString(fmt.Sprintf(" + API URL = %s\n", e.API_URL))
	sb.WriteString(fmt.Sprintf(" + Portal API Key = %s\n", e.PortalAPIKey))
	sb.WriteString(fmt.Sprintf(" + VPN Address = %s\n", e.VPNAddress))
	sb.WriteString(fmt.Sprintf(" + SSH Key File = %s\n", e.SSHKeyFile))
	sb.WriteString(fmt.Sprintf(" + Relay Backend URL = %s\n", e.RelayBackendURL))
	sb.WriteString(fmt.Sprintf(" + Relay Backend Public Key = %s\n", e.RelayBackendPublicKey))
	sb.WriteString(fmt.Sprintf(" + Relay Artifacts Bucket Name = %s\n", e.RelayArtifactsBucketName))
	sb.WriteString(fmt.Sprintf(" + Raspberry Backend URL = %s\n", e.RaspberryBackendURL))
	return sb.String()
}

func (e *Environment) Exists() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		handleRunTimeError(fmt.Sprintf("failed to read environment %v\n", err), 1)
	}

	envFilePath := path.Join(homeDir, ".next")

	if _, err := os.Stat(envFilePath); err != nil {
		return false
	}

	return true
}

func (e *Environment) Read() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		handleRunTimeError(fmt.Sprintf("failed to read environment %v\n", err), 1)
	}

	envFilePath := path.Join(homeDir, ".next")

	f, err := os.Open(envFilePath)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("failed to read environment %v\n", err), 1)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(e); err != nil {
		handleRunTimeError(fmt.Sprintf("failed to read environment %v\n", err), 1)
	}
}

func (e *Environment) Write() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		handleRunTimeError(fmt.Sprintf("failed to read environment %v\n", err), 1)
	}

	envFilePath := path.Join(homeDir, ".next")

	f, err := os.Create(envFilePath)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("failed to read environment %v\n", err), 1)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(e); err != nil {
		handleRunTimeError(fmt.Sprintf("failed to read environment %v\n", err), 1)
	}
}

func (e *Environment) Clean() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		handleRunTimeError(fmt.Sprintf("failed to clean environment %v\n", err), 1)
	}

	envFilePath := path.Join(homeDir, ".next")

	err = os.RemoveAll(envFilePath)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("failed to clean environment %v\n", err), 1)

	}
}

// -------------------------------------------------------------------------------------------

func getCostMatrix(env Environment, fileName string) {

	cost_matrix_binary := GetBinary(getAdminAPIKey(), fmt.Sprintf("%s/portal/cost_matrix", env.API_URL))

	os.WriteFile("cost.bin", cost_matrix_binary, 0644)

	w, err := os.Create("cost.html")
	if err != nil {
		panic(err)
	}

	defer w.Close()

	costMatrix := common.CostMatrix{}

	err = costMatrix.Read(cost_matrix_binary)
	if err != nil {
		panic(err)
	}

	const htmlHeader = `<!DOCTYPE html>
	<html lang="en">
	<head>
	  <meta charset="utf-8">
	  <title>Cost Matrix</title>
	  <style>
		table, th, td {
	      border: 1px solid black;
	      border-collapse: collapse;
	      text-align: center;
	      padding: 10px;
	    }
		cost{
      	  color: white;
   		}
		*{
	    font-family:Courier;
	    }
	  </style>
	</head>
	<body>`

	fmt.Fprintf(w, "%s\n", htmlHeader)

	fmt.Fprintf(w, "cost matrix:<br><br><table>\n")

	fmt.Fprintf(w, "<tr><td></td>")

	for i := range costMatrix.RelayNames {
		fmt.Fprintf(w, "<td><b>%s</b></td>", costMatrix.RelayNames[i])
	}

	fmt.Fprintf(w, "</tr>\n")

	for i := range costMatrix.RelayNames {
		fmt.Fprintf(w, "<tr><td><b>%s</b></td>", costMatrix.RelayNames[i])
		for j := range costMatrix.RelayNames {
			if i == j {
				fmt.Fprint(w, "<td bgcolor=\"lightgrey\"></td>")
				continue
			}
			nope := false
			costString := ""
			index := core.TriMatrixIndex(i, j)
			cost := costMatrix.Costs[index]
			if cost >= 0 && cost < 255 {
				costString = fmt.Sprintf("%d", cost)
			} else {
				nope = true
			}
			if nope {
				fmt.Fprintf(w, "<td bgcolor=\"red\"></td>")
			} else {
				fmt.Fprintf(w, "<td bgcolor=\"green\"><cost>%s</cost></td>", costString)
			}
		}
		fmt.Fprintf(w, "</tr>\n")
	}

	fmt.Fprintf(w, "</table>\n")

	const htmlFooter = `</body></html>`

	fmt.Fprintf(w, "%s\n", htmlFooter)
}

func optimizeCostMatrix(costMatrixFilename, routeMatrixFilename string, costThreshold int32) {

	costMatrixData, err := os.ReadFile(costMatrixFilename)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("could not read the cost matrix file: %v\n", err), 1)
	}

	var costMatrix common.CostMatrix

	err = costMatrix.Read(costMatrixData)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("error reading cost matrix: %v\n", err), 1)
	}

	numRelays := len(costMatrix.RelayIds)

	numDestRelays := 0
	for i := range costMatrix.DestRelays {
		if costMatrix.DestRelays[i] {
			numDestRelays++
		}
	}

	numCPUs := runtime.NumCPU()
	numSegments := numRelays
	if numCPUs < numRelays {
		numSegments = numRelays / 5
		if numSegments == 0 {
			numSegments = 1
		}
	}

	routeMatrix := &common.RouteMatrix{
		Version:            common.RouteMatrixVersion_Write,
		RelayIds:           costMatrix.RelayIds,
		RelayAddresses:     costMatrix.RelayAddresses,
		RelayNames:         costMatrix.RelayNames,
		RelayLatitudes:     costMatrix.RelayLatitudes,
		RelayLongitudes:    costMatrix.RelayLongitudes,
		RelayDatacenterIds: costMatrix.RelayDatacenterIds,
		DestRelays:         costMatrix.DestRelays,
		RouteEntries:       core.Optimize2(numRelays, numSegments, costMatrix.Costs, costMatrix.RelayDatacenterIds, costMatrix.DestRelays),
	}

	routeMatrixData, err := routeMatrix.Write()
	if err != nil {
		handleRunTimeError(fmt.Sprintf("could not write route matrix: %v", err), 1)
	}

	err = os.WriteFile(routeMatrixFilename, routeMatrixData, 0644)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("could not open the route matrix file for writing: %v\n", err), 1)
	}
}

func analyzeRouteMatrix(inputFile string) {

	routeMatrixFilename := "optimize.bin"

	routeMatrixData, err := os.ReadFile(routeMatrixFilename)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("could not read the route matrix file: %v\n", err), 1)
	}

	var routeMatrix common.RouteMatrix

	err = routeMatrix.Read(routeMatrixData)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("error reading route matrix: %v\n", err), 1)
	}

	analysis := routeMatrix.Analyze()

	fmt.Printf("RTT Improvement\n\n")

	fmt.Printf("    None: %.1f%%\n", analysis.RTTBucket_NoImprovement)
	fmt.Printf("    0-5ms: %.1f%%\n", analysis.RTTBucket_0_5ms)
	fmt.Printf("    5-10ms: %.1f%%\n", analysis.RTTBucket_5_10ms)
	fmt.Printf("    10-15ms: %.1f%%\n", analysis.RTTBucket_10_15ms)
	fmt.Printf("    15-20ms: %.1f%%\n", analysis.RTTBucket_15_20ms)
	fmt.Printf("    20-25ms: %.1f%%\n", analysis.RTTBucket_20_25ms)
	fmt.Printf("    25-30ms: %.1f%%\n", analysis.RTTBucket_25_30ms)
	fmt.Printf("    30-35ms: %.1f%%\n", analysis.RTTBucket_30_35ms)
	fmt.Printf("    35-40ms: %.1f%%\n", analysis.RTTBucket_35_40ms)
	fmt.Printf("    40-45ms: %.1f%%\n", analysis.RTTBucket_40_45ms)
	fmt.Printf("    45-50ms: %.1f%%\n", analysis.RTTBucket_45_50ms)
	fmt.Printf("    50ms+: %.1f%%\n", analysis.RTTBucket_50ms_Plus)

	fmt.Printf("\nRoute Summary:\n\n")

	fmt.Printf("    %d relays\n", len(routeMatrix.RelayIds))
	fmt.Printf("    %d total routes\n", analysis.TotalRoutes)
	fmt.Printf("    %.1f routes per-relay pair on average\n", analysis.AverageNumRoutes)
	fmt.Printf("    %.1f relays per-route on average\n", analysis.AverageRouteLength)
	fmt.Printf("    %.1f%% of relay pairs have only one route\n", analysis.OneRoutePercent)
	fmt.Printf("    %.1f%% of relay pairs have no direct route\n", analysis.NoDirectRoutePercent)
	fmt.Printf("    %.1f%% of relay pairs have no route\n", analysis.NoRoutePercent)

	fmt.Printf("\n")
}

func routes(src string, dest string) {

	routeMatrixFilename := "optimize.bin"

	routeMatrixData, err := os.ReadFile(routeMatrixFilename)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("could not read the route matrix file: %v\n", err), 1)
	}

	var routeMatrix common.RouteMatrix

	err = routeMatrix.Read(routeMatrixData)
	if err != nil {
		handleRunTimeError(fmt.Sprintf("error reading route matrix: %v\n", err), 1)
	}

	src_index := -1
	for i := range routeMatrix.RelayNames {
		if routeMatrix.RelayNames[i] == src {
			src_index = i
			break
		}
	}

	if src_index == -1 {
		handleRunTimeError(fmt.Sprintf("could not find source relay: %s\n", src), 1)
	}

	dest_index := -1
	for i := range routeMatrix.RelayNames {
		if routeMatrix.RelayNames[i] == dest {
			dest_index = i
			break
		}
	}

	if dest_index == -1 {
		handleRunTimeError(fmt.Sprintf("could not find destination relay: %s\n", src), 1)
	}

	index := core.TriMatrixIndex(src_index, dest_index)

	entry := routeMatrix.RouteEntries[index]

	fmt.Printf("routes from %s -> %s:\n\n", src, dest)

	hasRoutes := false

	for i := 0; i < int(entry.NumRoutes); i++ {
		routeRelays := ""
		numRouteRelays := int(entry.RouteNumRelays[i])
		if src_index < dest_index {
			for j := numRouteRelays - 1; j >= 0; j-- {
				routeRelayIndex := entry.RouteRelays[i][j]
				routeRelayName := routeMatrix.RelayNames[routeRelayIndex]
				routeRelays += routeRelayName
				if j != 0 {
					routeRelays += " - "
				}
			}
		} else {
			for j := 0; j < numRouteRelays; j++ {
				routeRelayIndex := entry.RouteRelays[i][j]
				routeRelayName := routeMatrix.RelayNames[routeRelayIndex]
				routeRelays += routeRelayName
				if j != numRouteRelays-1 {
					routeRelays += " - "
				}
			}
		}
		fmt.Printf(" + %d: %s\n", entry.RouteCost[i], routeRelays)
		hasRoutes = true
	}

	if !hasRoutes {
		fmt.Printf("(no routes exist)\n")
	}

	fmt.Printf("\n")
}

// -------------------------------------------------------------------------------------------

func ping() {
	url := fmt.Sprintf("%s/ping", env.API_URL)
	text := GetText(getAdminAPIKey(), url)
	fmt.Printf("%s\n\n", text)
}

// -------------------------------------------------------------------------------------------

func runCommand(command string, args []string) bool {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		return false
	}
	return true
}

func runCommandEnv(command string, args []string, env map[string]string) bool {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	finalEnv := os.Environ()
	for k, v := range env {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = finalEnv

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		fmt.Printf("\n\n")
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
			cmd.Wait()
		}
		os.Exit(1)
	}()

	err := cmd.Run()

	if err != nil {
		return false
	}

	return true
}

// stdout is the string return value
// stderr is contained in the error return value or nil if the command exited successfully
func runCommandGetOutput(command string, args []string, env map[string]string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command(command, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	finalEnv := os.Environ()
	for k, v := range env {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = finalEnv

	err := cmd.Run()

	stdoutStr := strings.Trim(stdout.String(), "\r\n")
	if err != nil {
		stderrStr := strings.Trim(stderr.String(), "\r\n")
		return stdoutStr, fmt.Errorf("%v, %s", err, stderrStr)
	}

	return stdoutStr, nil
}

func runCommandQuiet(command string, args []string, stdoutOnly bool) (bool, string) {
	cmd := exec.Command(command, args...)

	stdoutReader, err := cmd.StdoutPipe()
	if err != nil {
		return false, ""
	}

	var stderrReader io.ReadCloser
	if !stdoutOnly {
		stderrReader, err = cmd.StderrPipe()
		if err != nil {
			return false, ""
		}
	}

	var wait sync.WaitGroup
	var mutex sync.Mutex

	output := ""

	stdoutScanner := bufio.NewScanner(stdoutReader)
	wait.Add(1)
	go func() {
		for stdoutScanner.Scan() {
			mutex.Lock()
			output += stdoutScanner.Text() + "\n"
			mutex.Unlock()
		}
		wait.Done()
	}()

	if !stdoutOnly {
		stderrScanner := bufio.NewScanner(stderrReader)
		wait.Add(1)
		go func() {
			for stderrScanner.Scan() {
				mutex.Lock()
				output += stderrScanner.Text() + "\n"
				mutex.Unlock()
			}
			wait.Done()
		}()
	} else {
		cmd.Stderr = os.Stderr
	}

	err = cmd.Start()
	if err != nil {
		return false, output
	}

	wait.Wait()

	err = cmd.Wait()
	if err != nil {
		return false, output
	}

	return true, output
}

func bash(command string) bool {
	return runCommand("bash", []string{"-c", command})
}

func bashQuiet(command string) string {
	_, output := runCommandQuiet("bash", []string{"-c", command}, false)
	return output
}

func secureShell(user string, address string, port int) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		handleRunTimeError(fmt.Sprintln("error: could not find ssh"), 1)
	}
	args := make([]string, 4)
	args[0] = "ssh"
	args[1] = "-p"
	args[2] = fmt.Sprintf("%d", port)
	args[3] = fmt.Sprintf("%s@%s", user, address)
	env := os.Environ()
	err = syscall.Exec(ssh, args, env)
	if err != nil {
		handleRunTimeError(fmt.Sprintln("error: failed to exec ssh"), 1)
	}
}

// level 0: user error
// level 1: program error
func handleRunTimeError(msg string, level int) {
	fmt.Printf(msg)
	fmt.Printf("\n\n")
	os.Exit(level)
}

var env Environment

func getKeyValue(envFile string, keyName string) string {
	value := bashQuiet(fmt.Sprintf("cat %s | awk -v key=%s -F= '$1 == key { sub(/^[^=]+=/, \"\"); print }'", envFile, keyName))
	if len(value) < 1 {
		return ""
	}
	value = value[:len(value)-1]
	if value[0] == '"' || value[0] == '\'' {
		value = value[1 : len(value)-1]
	}
	return value
}

// --------------------------------------------------------------------------------------

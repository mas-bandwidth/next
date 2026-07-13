package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"

	"github.com/joho/godotenv"
)

// simple commands are a single bash one-liner

var simpleCommands = map[string]string{
	"test-sdk":                    "cd ./dist && ./test",
	"magic-backend":               "HTTP_PORT=41007 ./dist/magic_backend",
	"relay-gateway":               "HTTP_PORT=30000 ./dist/relay_gateway",
	"server-backend":              "HTTP_PORT=40000 ./dist/server_backend",
	"server":                      "cd dist && ./server",
	"raspberry-backend":           "HTTP_PORT=40100 ./dist/raspberry_backend",
	"raspberry-client":            "cd dist && ./raspberry_client",
	"raspberry-server":            "cd dist && ./raspberry_server",
	"sql-create":                  "psql -U developer postgres -f ./schemas/sql/create.sql -v ON_ERROR_STOP=1",
	"sql-destroy":                 "psql -U developer postgres -f ./schemas/sql/destroy.sql -v ON_ERROR_STOP=1",
	"sql-local":                   "psql -U developer postgres -f ./schemas/sql/local.sql -v ON_ERROR_STOP=1",
	"sql-docker":                  "psql -U developer postgres -f ./schemas/sql/docker.sql -v ON_ERROR_STOP=1",
	"sql-staging":                 "psql -U developer postgres -f ./schemas/sql/staging.sql -v ON_ERROR_STOP=1",
	"extract-database":            "go run tools/extract_database/extract_database.go",
	"generate-staging-sql":        "go run tools/generate_staging_sql/generate_staging_sql.go",
	"func-server":                 "cd dist && ./func_server",
	"func-client":                 "cd dist && ./func_client",
	"func-backend":                "cd dist && ./func_backend",
	"load-test-portal":            "go run tools/load_test_portal/load_test_portal.go",
	"load-test-redis-data":        "go run tools/load_test_redis_data/load_test_redis_data.go",
	"load-test-redis-time-series": "go run tools/load_test_redis_time_series/load_test_redis_time_series.go",
	"load-test-redis-counters":    "go run tools/load_test_redis_counters/load_test_redis_counters.go",
	"load-test-optimize":          "go run tools/load_test_optimize/load_test_optimize.go",
	"load-test-route-matrix":      "go run tools/load_test_route_matrix/load_test_route_matrix.go",
	"load-test-relay-manager":     "go run tools/load_test_relay_manager/load_test_relay_manager.go",
	"load-test-crypto-box":        "go run tools/load_test_crypto_box/load_test_crypto_box.go",
	"load-test-crypto-sign":       "go run tools/load_test_crypto_sign/load_test_crypto_sign.go",
	"load-test-server-update":     "go run tools/load_test_server_update/load_test_server_update.go",
	"load-test-session-update":    "go run tools/load_test_session_update/load_test_session_update.go",
	"load-test-relays":            "cd dist && ./load_test_relays",
	"load-test-servers":           "cd dist && ./load_test_servers",
	"load-test-sessions":          "cd dist && ./load_test_sessions",
	"load-relay-manager":          "go run tools/load_relay_manager/load_relay_manager.go",
	"soak-test-relay":             "cd dist && ./soak_test_relay stop",
	"config-amazon":               "go run sellers/amazon.go",
	"config-google":               "go run sellers/google.go",
	"config-akamai":               "go run sellers/akamai.go",
	"ip2location":                 "cd dist && ./ip2location",
	"redis-cluster":               "go run tools/redis_cluster/redis_cluster.go",
	"redis-time-series":           "docker run -p 6379:6379 --rm redis/redis-stack-server:latest",
	"autodetect":                  "cd dist && HTTP_PORT=60000 ./autodetect",
}

// special commands take arguments or need logic beyond a one-liner

var specialCommands = map[string]func(args []string){
	"test":               func(args []string) { test() },
	"api":                func(args []string) { api() },
	"relay":              func(args []string) { relay() },
	"relay-backend":      func(args []string) { servicePort("relay_backend", "30001") },
	"session-cruncher":   func(args []string) { servicePort("session_cruncher", "40200") },
	"server-cruncher":    func(args []string) { servicePort("server_cruncher", "40300") },
	"client":             func(args []string) { client() },
	"portal":             func(args []string) { portal() },
	"happy-path":         func(args []string) { happy_path() },
	"happy-path-no-wait": func(args []string) { happy_path_no_wait() },
	"pubsub-emulator":    func(args []string) { pubsub_emulator() },
	"bigquery-emulator":  func(args []string) { bigquery_emulator() },
	"func-test-sdk":      func(args []string) { funcTest("func_test_sdk", args) },
	"func-test-relay":    func(args []string) { funcTest("func_test_relay", args) },
	"func-test-backend":  func(args []string) { funcTest("func_test_backend", args) },
	"func-test-api":      func(args []string) { funcTest("func_test_api", args) },
	"func-test-terraform": func(args []string) {
		funcTest("func_test_terraform", args)
	},
	"func-test-portal":   func(args []string) { funcTest("func_test_portal", args) },
	"func-test-database": func(args []string) { funcTest("func_test_database", args) },
}

func main() {

	args := os.Args

	if len(args) < 2 || (len(args) == 2 && args[1] == "help") {
		help()
		return
	}

	err := godotenv.Load(".env")
	if err != nil {
		fmt.Printf("error: could not load .env file")
		os.Exit(1)
	}

	command := args[1]

	if special, ok := specialCommands[command]; ok {
		special(args[2:])
		return
	}

	if line, ok := simpleCommands[command]; ok {
		bash(line)
		return
	}

	fmt.Printf("\nunknown command\n\n")
}

func help() {
	fmt.Printf("\nsyntax:\n\n    run <action> [args]\n\n")
}

// ------------------------------------------------------------------------------

var cmd *exec.Cmd

func bash(command string) {

	cmd = exec.Command("bash", "-c", command)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH=.")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		if cmd.Process != nil {
			fmt.Printf("\n\n")
			if err := cmd.Process.Signal(sig); err != nil {
				fmt.Printf("error trying to signal child process: %v\n", err)
			}
			cmd.Wait()
		}
		os.Exit(1)
	}()

	if err := cmd.Run(); err != nil {
		fmt.Printf("error: failed to run command: %v\n", err)
		os.Exit(1)
	}
}

func bash_ignore_result(command string) {
	cmd = exec.Command("bash", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Run()
}

func RunCommand(command string, args []string) (bool, string) {

	cmd := exec.Command(command, args...)

	stdoutReader, err := cmd.StdoutPipe()
	if err != nil {
		return false, ""
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

	cmd.Stderr = os.Stderr

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

func bash_output(command string) (bool, string) {
	return RunCommand("bash", []string{"-c", command})
}

// ------------------------------------------------------------------------------

func test() {
	fmt.Printf("\n")
	bash("go test ./modules/...")
	fmt.Printf("\n")
}

// servicePort runs a dist binary with HTTP_PORT from the environment, falling back
// to the service's default port
func servicePort(binary string, defaultPort string) {
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = defaultPort
	}
	bash(fmt.Sprintf("HTTP_PORT=%s ./dist/%s", httpPort, binary))
}

func getAPIPrivateKey() string {
	var env Environment
	env.Read()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("error: could not get users home dir: %v\n\n", err)
		os.Exit(1)
	}
	filename := fmt.Sprintf("%s/secrets/%s-api-private-key.txt", homeDir, env.Name)
	_, err = os.Stat(filename)
	if env.Name == "local" && os.IsNotExist(err) {
		// local env during setup. user has not called "next config" yet. use a default value so they can run happy path locally
		return "fhWwyybJcUVgvewtGqepaHCwpNdAeCBxsYXuPNFNgSaIZbgqQJKOuuQfzuHCJKDB"
	}
	// common path: secrets dir exists. get generated API private key from there
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("error: could not read api private key from secrets dir: %v\n\n", err)
		os.Exit(1)
	}
	return string(data)
}

func api() {
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "50000"
	}
	apiPrivateKey := getAPIPrivateKey()
	fmt.Printf("api private key = '%s'\n", apiPrivateKey)
	bash(fmt.Sprintf("HTTP_PORT=%s API_PRIVATE_KEY=%s ./dist/api", httpPort, apiPrivateKey))
}

func relay() {
	relayPort := os.Getenv("RELAY_PORT")
	if relayPort == "" {
		relayPort = "2000"
	}
	bash(fmt.Sprintf("cd dist && RELAY_PUBLIC_ADDRESS=127.0.0.1:%s ./relay-userspace-debug", relayPort))
}

func happy_path() {
	fmt.Printf("\ndon't worry. be happy.\n\n")
	bash("go run ./tools/happy_path/happy_path.go")
}

func happy_path_no_wait() {
	fmt.Printf("\ndon't worry. be happy.\n\n")
	bash("go run ./tools/happy_path/happy_path.go 1")
}

func client() {
	var env Environment
	env.Read()
	if env.Name == "local" {
		bash("cd dist && ./client")
		return
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("error: could not get users home dir: %v\n\n", err)
		os.Exit(1)
	}
	filename := fmt.Sprintf("%s/secrets/%s-project-id.txt", homeDir, env.Name)
	projectId, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("\nerror: could not load project file '%s'\n\n", filename)
		os.Exit(1)
	}
	_, output := bash_output(fmt.Sprintf("gcloud compute addresses list --project %s", projectId))
	lines := strings.Split(output, "\n")
	for i := range lines {
		if strings.Contains(lines[i], "test-server-address") {
			values := strings.Fields(lines[i])
			if len(values) >= 2 {
				connectAddress := values[1]
				bash(fmt.Sprintf("cd dist && NEXT_CONNECT_ADDRESS=%s:30000 ./client", connectAddress))
				return
			}
		}
	}
	fmt.Printf("\nerror: could not find test server address for %s\n\n", env.Name)
	os.Exit(1)
}

func portal() {
	var env Environment
	env.Read()
	bash(fmt.Sprintf("cd portal && yarn serve-%s", env.Name))
}

func pubsub_emulator() {
	bash_ignore_result("pkill -f pubsub-emulator")
	bash("gcloud beta emulators pubsub start --project=local --host-port=127.0.0.1:9000")
}

func bigquery_emulator() {
	bash_ignore_result("pkill -f bigquery-emulator")
	bash("bigquery-emulator --project=local --dataset=local")
}

// funcTest runs a functional test binary from dist, once per named test, or once
// with no arguments to run the whole suite
func funcTest(binary string, tests []string) {
	command := "cd dist && ./" + binary
	if len(tests) == 0 {
		bash(command)
		return
	}
	for _, test := range tests {
		bash(fmt.Sprintf("%s %s", command, test))
	}
}

// ------------------------------------------------------------------------------

// only Name is read out of ~/.next -- the file has more fields (written by the
// next tool) but nothing here uses them

type Environment struct {
	Name string `json:"name"`
}

func (e *Environment) Read() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	envFilePath := path.Join(homeDir, ".next")

	f, err := os.Open(envFilePath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(e); err != nil {
		panic(err)
	}
}

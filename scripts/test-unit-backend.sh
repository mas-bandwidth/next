#!/bin/bash

firestorfeSessionID=0
pubsubSessionID=0

if [[ ! -z "$FIRESTORE_EMULATOR_HOST" ]]; then
    printf "Starting firestore emulator...\n\n"
    setsid gcloud beta emulators firestore start --host-port $FIRESTORE_EMULATOR_HOST --no-user-output-enabled &
    firestoreSessionID=$! # Get the session ID of this process so we can close it later

    # Trap kill the process group so all firestore emulator processes are closed properly
    trap "kill -- -$firestoreSessionID" EXIT
    sleep 3
fi

if [[ ! -z "$PUBSUB_EMULATOR_HOST" ]]; then
    printf "Starting pubsub emulator...\n\n"
    setsid gcloud beta emulators pubsub start --host-port $PUBSUB_EMULATOR_HOST --no-user-output-enabled &
    pubsubSessionID=$! # Get the session ID of this process so we can close it later

    # Trap kill the process group so all pubsub emulator processes are closed properly
    trap "kill -- -$firestoreSessionID -$pubsubSessionID" EXIT
    sleep 3
fi

printf "Running go tests:\n\n"
go test  ./... -coverprofile ./cover.out
testResult=$?
if [ ! $testResult -eq 0 ]; then
    exit $testResult
fi

printf "\n\nCoverage results of go tests:\n\n"
go tool cover -func ./cover.out
printf "\n"

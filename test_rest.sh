#!/bin/bash

SVC_PORT=$( grep -w rest config.json | awk -F\  '{ print $2 }' | tr -d \, )

function curl_call()
{
    route=$1
    shift 1

    method=""
    if [[ "$1" == "GET" ]] || \
        [[ "$1" == "PUT" ]] || \
        [[ "$1" == "POST" ]] || \
        [[ "$1" == "DELETE" ]]; then
            method="-X $1"
            shift 1
    fi

    if [[ $# -ge 1 ]]; then
        echo "Running: curl -s -i http://localhost:$SVC_PORT/$route $method -H \"Content-Type: application/json\" $data"
        curl -i -s http://localhost:$SVC_PORT/$route $method \
            -H "Content-Type: application/json" \
            -d "$*"
    else
        echo "Running: curl -s -i http://localhost:$SVC_PORT/$route $method -H \"Content-Type: application/json\""
        curl -i -s http://localhost:$SVC_PORT/$route $method \
            -H "Content-Type: application/json"
    fi
    echo ""
}

if [[ "$SVC_PORT" == "" ]]; then
    echo "Failed to find rest service port, aborting..."
    exit
fi
echo "Found rest service port: $SVC_PORT"

## Test: Create a locker & secret, retrieve the secret, update it and retrieve the updated secret.
curl_call config GET
curl_call locker '{"locker_id": "l1"}'
curl_call secret '{"locker_id": "l1", "secret_key": "s1", "secret_blob": "b1"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s1"}'
curl_call secret PUT '{"locker_id": "l1", "secret_key": "s1", "secret_blob": "b2"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s1"}'

## Test: Create a new secret, retrieve it, delete it & try to retrieve it again.
curl_call secret '{"locker_id": "l1", "secret_key": "s2", "secret_blob": "b2"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s2"}'
curl_call secret DELETE '{"locker_id": "l1", "secret_key": "s2"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s2"}'

# Test: Delete the locker, try to retrieve the secret.
curl_call locker DELETE '{"locker_id": "l1"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s1"}'


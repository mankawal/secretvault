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

    data=$*
    echo "Running: curl -s -v http://localhost:$SVC_PORT/$route $method -H "Content-Type: application/json" -d $data"
    curl -s http://localhost:$SVC_PORT/$route $method \
        -H "Content-Type: application/json" \
        -d "$data"
    echo ""
}

if [[ "$SVC_PORT" == "" ]]; then
    echo "Failed to find rest service port, aborting..."
    exit
fi
echo "Found rest service port: $SVC_PORT"

curl_call locker '{"locker_id": "l1"}'
curl_call secret '{"locker_id": "l1", "secret_key": "s1", "secret_blob": "b1"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s1"}'
curl_call secret PUT '{"locker_id": "l1", "secret_key": "s1", "secret_blob": "b2"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s1"}'


curl_call secret '{"locker_id": "l1", "secret_key": "s2", "secret_blob": "b2"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s2"}'
curl_call secret DELETE '{"locker_id": "l1", "secret_key": "s2"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s2"}'

curl_call locker DELETE '{"locker_id": "l1"}'
curl_call secret GET '{"locker_id": "l1", "secret_key": "s1"}'


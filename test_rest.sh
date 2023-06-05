#!/bin/bash

SVC_PORT_ADMIN=$( \
    grep -A15 -w serve_admin config.json | grep rest | \
    awk -F\  '{ print $2 }' | tr -d \, 
)
SVC_PORT=$( \
    grep -A15 -w serve config.json | \
    grep rest | awk -F\  '{ print $2 }' | tr -d \,s
)
TOKEN=""

function curl_call()
{
    is_admin_call=$1
    route=$2
    shift 2
    
    svc_port=$SVC_PORT
    if [[ $is_admin_call -eq 1 ]] ; then
        svc_port=$SVC_PORT_ADMIN
    fi

    method=""
    if [[ "$1" == "GET" ]] || \
        [[ "$1" == "PUT" ]] || \
        [[ "$1" == "POST" ]] || \
        [[ "$1" == "DELETE" ]]; then
            method="-X $1"
            shift 1
    fi

    if [[ $# -ge 1 ]]; then
        echo "Running: curl -s -i http://localhost:$svc_port/$route $method -H \"Content-Type: application/json\" -d '$*'"
        curl -i -s http://localhost:$svc_port/$route $method \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d "$*"
    else
        echo "Running: curl -s -i http://localhost:$svc_port/$route $method -H \"Content-Type: application/json\""
        curl -i -s http://localhost:$svc_port/$route $method \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN"
    fi
    echo -e "\n"
}

if [[ "$SVC_PORT" == "" ]] || [[ "$SVC_PORT_ADMIN" == "" ]]; then
    echo "Failed to find one of the rest service port, aborting..."
    exit
fi
echo "Found rest service port: $SVC_PORT, admin: $SVC_PORT_ADMIN"

function get_auth_token()
{
    auth_req='{"vault_id": "'$1'", "user_name": "'$2'","user_context": "'$3'"}"'

    curl -i -s http://localhost:$SVC_PORT/auth -X GET \
        -H "Content-Type: application/json" \
        -d '{"vault_id": "'$1'", "user_name": "'$2'","user_context": "'$3'"}"' | \
        tail -1 | jq '.token' | tr -d \"
}

## Test: Get the service config
curl_call 0 config GET

vault="rest_v1"
user="rest_user1"
userctx="rest_user1_attrib1"
context='{"vault_id": "'$vault'", "user_name": "'$user'", "user_context": "'$userctx'"}'

## Test: Create a vault and a user.
curl_call 1 vault POST '{"vault_id": "'$vault'"}'
curl_call 1 metadata POST '{"vault_id": "'$vault'", "name": "'$user'", "value": "'$userctx'"}'

TOKEN=$( get_auth_token $vault $user $userctx )
echo "Using bearer token: $TOKEN"

# ## Test: Create a locker & secret, retrieve the secret, update it and retrieve the updated secret.
curl_call 0 locker POST '{"context": '$context', "locker_id": "l1", "locker_contents": "create_test"}'
curl_call 0 locker GET  '{"context": '$context', "locker_id": "l1"}'
curl_call 0 locker PUT  '{"context": '$context', "locker_id": "l1", "locker_contents": "update_test"}'
curl_call 0 locker GET  '{"context": '$context', "locker_id": "l1"}'

## Test: delete locker & try to retrieve it again.
curl_call 0 locker POST   '{"context": '$context', "locker_id": "l1", "locker_contents": "delete_test"}'
curl_call 0 locker GET    '{"context": '$context', "locker_id": "l1"}'
curl_call 0 locker DELETE '{"context": '$context', "locker_id": "l1"}'
curl_call 0 locker GET    '{"context": '$context', "locker_id": "l1"}'

## Test: Cancel locker deletion, retrieve it
curl_call 1 pending_delete PUT '{"vault_id": "'$vault'", "locker_id": "l1"}'
curl_call 0 locker GET    '{"context": '$context', "locker_id": "l1"}'

# Test: Delete the locker, complete delete and re-create the locker.
curl_call 0 locker DELETE '{"context": '$context', "locker_id": "l1"}'
curl_call 1 pending_delete DELETE '{"vault_id": "'$vault'", "locker_id": "l1"}'
curl_call 0 locker POST '{"context": '$context', "locker_id": "l1", "locker_contents" : "l1_value"}'

curl_call 1 vault DELETE '{"vault_id": "'$vault'", "user_name": "'$user'", "user_context": "'$userctx'"}'


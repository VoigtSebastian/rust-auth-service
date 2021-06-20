#!/bin/bash

set -e

export POSTGRES_HOSTNAME="localhost"
export POSTGRES_PORT="5432"
export POSTGRES_USER="postgres"
export POSTGRES_DB="auth_service_db"
export PGPASSWORD="password"
export CONTAINER_NAME="auth_service_db"

function start_container {
    docker run \
        --name=$CONTAINER_NAME \
        -e POSTGRES_DB=$POSTGRES_DB \
        -e POSTGRES_PASSWORD=$PGPASSWORD \
        -p $POSTGRES_PORT:5432 \
        -d postgres:11-alpine
}

function database_up {
    psql \
        -U $POSTGRES_USER \
        -h $POSTGRES_HOSTNAME \
        $POSTGRES_DB \
        -a -f sql/up.sql
}

function database_down {
    psql \
        -U $POSTGRES_USER \
        -h $POSTGRES_HOSTNAME \
        $POSTGRES_DB \
        -a -f sql/down.sql
}

function database_command {
    psql \
        -U $POSTGRES_USER \
        -h $POSTGRES_HOSTNAME \
        $POSTGRES_DB \
        -c \
        "$1"
}

function database_add_user {
    database_command "INSERT INTO users (username, password, registration_date) VALUES ('$1', crypt('$2', gen_salt('bf')), NOW());"
}

function database_add_session {
    database_command "INSERT INTO sessions (session_id, user_id, expiration_date) VALUES (gen_random_uuid(), $1, NOW());"
}

function database_add_capability {
    database_command "INSERT INTO capabilities (user_id, label) VALUES ($1, '$2');"
}

function list_exipired_sessions {
    database_command "select * from sessions WHERE expiration_date < NOW();"
}

# Normally you would check username AND password
function select_user_by_password {
    database_command "select * from users where password = crypt('$1', password);"
}

if [ $# == 0 ] || [ "$1" == "testenv" ] && [ "$2" == "restart" ]; then
    docker container stop $CONTAINER_NAME
    docker container rm $CONTAINER_NAME
    start_container
    sleep 5
    database_up

elif [ $# == 0 ] || [ "$1" == "container" ] && [ "$2" == "start" ]; then
    start_container

elif [ "$1" == "container" ] && [ "$2" == "rm" ]; then
    docker container rm $CONTAINER_NAME

elif [ "$1" == "container" ] && [ "$2" == "stop" ]; then
    docker container stop $CONTAINER_NAME

elif [ "$1" == "db" ] || [ "$1" == "db" ] && [ "$2" == "up" ]; then
    database_up

elif [ "$1" == "db" ] && [ "$2" == "down" ]; then
    database_down

elif [ "$1" == "insert" ] && [ "$2" == "user" ] && [ $# == 4 ]; then
    echo "Inserting new user with username $3 and password $4"
    database_add_user "$3" "$4"

elif [ "$1" == "insert" ] && [ "$2" == "session" ] && [ $# == 3 ]; then
    echo "Inserting session for user with user_id $3"
    database_add_session "$3"

elif [ "$1" == "insert" ] && [ "$2" == "cap" ] && [ $# == 4 ]; then
    echo "Inserting capability for user with user_id $3"
    database_add_capability "$3" "$4"

elif [ "$1" == "list" ] && [ "$2" == "expired" ]; then
    echo "Listing expired sessions"
    list_exipired_sessions

elif [ "$1" == "list" ] && [ "$2" == "user-by-password" ] && [ $# == 3 ]; then
    select_user_by_password $3

elif [ "$1" == "connect" ]; then
    echo "Connecting to postgres database"
    psql $(./automation.sh psql-uri)

elif [ "$1" == "psql-uri" ]; then
    echo "postgres://$POSTGRES_USER:$PGPASSWORD@$POSTGRES_HOSTNAME:$POSTGRES_PORT/$POSTGRES_DB"

elif [ "$1" == "test" ]; then
    cargo test --workspace -- --ignored

elif [ "$1" == "doctest" ]; then
    cargo test --workspace --doc

elif [ "$1" == "doc" ]; then
    cargo doc --workspace --no-deps --document-private-items --open

elif [ "$1" == "gencert" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'

else
    echo "Unkown argument combination"
    echo "Development and automation script"
fi

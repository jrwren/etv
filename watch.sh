#!/bin/bash

trap k SIGINT

k() {
    kill $PID
}
go build -o app .
./app & PID=$!
while inotifywait -q -r -e modify *.go
do kill "$PID"
    go build -o app .
    ./app &
    PID=$!
done

# etv
web service for local control of my home server

In a sense, this is my home server dashboard.

## web services

The web services control the ISC BIND DNS Server by editing the named.conf.local file
from a standard ubuntu/debian config. This allowed me to block or unblock various sites.
It also blocks some network hosts using iptables.

## UI

The UI is simple HTML and an included typescript file. Build with `npx tsc index.ts`

## typescript

No -g install for this or anything. `npm install typescript --save-dev` was done.  `npm install` will restore it if node_modules is deleted. I'm a JS/TS noob, can you tell?

build: index.js ~/go/bin/etv


~/go/bin/etv: main.go index.js
	go install .
index.js: index.ts
	npx tsc index.ts

cert.pem:
	openssl req -newkey rsa:2048 \
  -new -nodes -x509 \
  -days 3650 \
  -out cert.pem \
  -keyout key.pem \
  -subj "/C=US/ST=Michigan/L=Ann Arbor/O=XMTP/OU=Your Unit/CN=localhost"

watch:
	watch.sh

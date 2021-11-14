build: index.js ~/go/bin/etv


~/go/bin/etv: main.go
	go install .
index.js: index.ts
	npx tsc index.ts

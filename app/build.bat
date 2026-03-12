SET GOOS=linux
SET GOARCH=amd64
go build -o Hysteria2
SET GOOS=windows
SET GOARCH=amd64
go build -o Hysteria2.exe

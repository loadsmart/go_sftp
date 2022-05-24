module github.com/loadsmart/go_sftp

go 1.17

require (
	github.com/kr/fs v0.1.0 // indirect
	github.com/pkg/sftp v1.13.4
	golang.org/x/crypto v0.0.0-20220518034528-6f7dac969898
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
)

replace golang.org/x/crypto => ./crypto

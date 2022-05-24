# Go sftp
SFTP Client implementation for go, compatible with Encryption Algorithm DSA key length 2048, 3072, 4096
# When to use this repo
By default, this repo is not aiming to replace the built in implementation available in go with the package crypto. 
This package is intended to add the simple compatibility of the DSA key kength of 2048,3072 and 4096 which the golang crypto package doesn't support by default.
This PR https://github.com/golang/crypto/pull/204 should solve the problem eventually when finally merged.

PLEASE avoid using this repo as implementation as SFTP connection. This is only a workaround to add the key length compatibility.

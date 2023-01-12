## Envoy Egress MITM

A proof of concept that:
- Starts as a L4 SNI forward proxy
- Mints self signed certificates based on SNI
- Hijacks/MITMs subsequent requests for the given SNI host


This is highly experimental.

## Getting started

#### Running
```bash
# Download deps
go mod download

# Create root and intermediate CA
cd cfssl
go run github.com/cloudflare/cfssl/cmd/cfssl gencert -initca ca.json | go run github.com/cloudflare/cfssl/cmd/cfssljson -bare ca
go run github.com/cloudflare/cfssl/cmd/cfssl gencert -initca intermediate-ca.json | go run github.com/cloudflare/cfssl/cmd/cfssljson -bare intermediate-ca
go run github.com/cloudflare/cfssl/cmd/cfssl sign -ca ca.pem -ca-key ca-key.pem -config cfssl.json -profile intermediate-ca intermediate-ca.csr | go run github.com/cloudflare/cfssl/cmd/cfssljson -bare intermediate-ca
# rename keys
mv ca-key.pem ca.key
mv intermediate-ca-key.pem intermediate-ca.key
# rename certificates
mv ca.pem ca.crt
mv intermediate-ca.pem intermediate-ca.crt
# combine cacertificates
cat ca.crt >> combined.crt
cat intermediate-ca.crt >> combined.crt
cd ..

# Start up Envoy + ALS service
docker-compose up --force-recreate --build -d --wait
```

#### Demo
```bash
# Make some requests
curl -sv -o /dev/null https://www.google.com --connect-to www.google.com:443:localhost:8443

# Second request should fail
curl -sv -o /dev/null https://www.google.com --connect-to www.google.com:443:localhost:8443

# Try again with self signed CA
curl -sv -o /dev/null https://www.google.com --connect-to www.google.com:443:localhost:8443 --cacert ./cfssl/combined.crt


# Repeat for any other hosts of your liking
# First request over L4
curl -sv -o /dev/null https://www.reddit.com --connect-to www.reddit.com:443:localhost:8443

# Second request fails
curl -sv -o /dev/null https://www.reddit.com --connect-to www.reddit.com:443:localhost:8443

# Request with self signed CA goes through
curl -sv -o /dev/null https://www.reddit.com --connect-to www.reddit.com:443:localhost:8443 --cacert ./cfssl/combined.crt
```

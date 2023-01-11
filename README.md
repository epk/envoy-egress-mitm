## Envoy Egress MITM

WIP (really scrappy)

A proof of concept Envoy configured as a L4 SNI forward proxy that lazily mints self signed certificates based on SNI.

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
mkdir -p tmp
docker-compose up -d --wait
```

#### Demo
```bash
# Make some requests
curl -s -o /dev/null https://google.com --connect-to google.com:443:localhost:8443
curl -s -o /dev/null https://twitter.com --connect-to twitter.com:443:localhost:8443

# Check for certificates
ls -alR tmp
```

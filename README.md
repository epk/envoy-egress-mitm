## Envoy Egress MITM

WIP

A proof of concept for Envoy starting as an L4 egress proxy that mints certificates based on SNI


#### Getting started

```bash
# Download deps
go mod download

# Create Root CA and Intermediate CA
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
docker-compose up -d

# Make some requests
curl -s -o /dev/null -v https://google.com --connect-to google.com:443:localhost:8443
curl -s -o /dev/null -v https://twitter.com --connect-to twitter.com:443:localhost:8443

# Check for certificates
ls /tmp
```

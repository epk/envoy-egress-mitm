## To validate config
```
docker run -v $(pwd)/envoy/config.yaml:/etc/envoy/envoy.yaml --rm cgr.dev/chainguard/envoy envoy --config-path /etc/envoy/envoy.yaml --mode validate
```

# pi_block_analyser
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "urmelausmall/pi-block-analyser:latest" \
  -t "urmelausmall/pi-block-analyser:6.1" \
  --push \
  .
VERSION=$(cat package.json | grep '"version":' | awk -F'"' '{print $4}')
docker build -t relaybox/auth:latest -t relaybox/auth:$VERSION .

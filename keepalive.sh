#!/bin/bash

URL="https://auth-server-projekt2-1-0-0-1.onrender.com/"
INTERVAL=300   # 300 sekunder = 5 minuter

echo "Startar keep-alive mot $URL"
echo "Tryck Ctrl+C för att avsluta"

while true
do
  echo "[$(date)] Pingar..."

  curl -s -o /dev/null -w "Status: %{http_code}\n" "$URL"

  sleep $INTERVAL
done
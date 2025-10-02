./.github/scripts/init-temp-keys.sh
sudo cp ./keys/localhost.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates

# Kill existing containers and start fresh
sudo docker ps -aq | sudo xargs -r docker rm -f
sudo docker compose up -d --wait

sleep 4

go run ./service provision keycloak
go run ./service provision fixtures
go run ./service start &
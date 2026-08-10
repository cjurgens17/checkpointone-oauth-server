# Start Docker Compose
docker compose up -d

# Current Testing URL for Google OpenID
http://localhost:5000/authorize?response_type=code&client_id=client_sdlkfj234kdjf2l34&redirect_uri=http://localhost:4200/callback&scope=openid%20email%20profile&state=teststate123&connection=google-oauth2&code_challenge=testchallenge123&code_challenge_method=S256

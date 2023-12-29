# OAuth2-server
Oauth2 Authorization server

# Sample cURL request
curl --location 'http://localhost:9999/oauth2/token' \
--header 'X_LOGIN_ID: user123' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic cG9zdG1hbjpwb3N0bWFuLXNlY3JldA==' \
--header 'Cookie: JSESSIONID=D154F40CB5928AA134B4EA5F90F849A8' \
--data-urlencode 'grant_type=client_credentials' \
--data-urlencode 'scope=READ'

# Sample response
{
    "access_token": "eyJraWQiOiI0ZWMzYTdhMi1iYzViLTQ3NmMtYjZiMC01ODJmYzE5OTE2ZDkiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwb3N0bWFuIiwiYXVkIjoicG9zdG1hbiIsIm5iZiI6MTcwMzgxNzI4NCwibG9naW5JZCI6InVzZXIxMjMiLCJyb2xlIjoiQURNSU4iLCJzY29wZSI6WyJSRUFEIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTA5MSIsImV4cCI6MTcwMzgxNzQwNCwiaWF0IjoxNzAzODE3Mjg0LCJqdGkiOiIwOGYwMTUxYy03OGEwLTRiMDItYTdlNy0zOTdhODE2OTcyMTIifQ.qMGyAoUBDryX-CyoTnKtBQ0DuF1OBNnB2byL4Z84Q6Pryad1n4Y4j0nywhTbhxhI_zwpZFCvoy_ltc5TArK_97kr0F6H66mQW3M872YMzMBJZhlWY8jQjVZ7mf1-zTc0rLYPJwDepgqysJd4r7LD-hkyItgwUwu3lJt9wahQBDpApNGcVWox5xV3t0fZg_wqGWmysSKRNaAjCam8-COtonJvu2zKyyKfsY1kStJeyH8O82lkpjGoKhY5fHF5korfQlCjOYNUZFMXIaRhspisLbrH6mLp5UbQsJ0bc21xw5qe_jmvm12JSMGOfTlRBKkP4-m_Tmwr1gc4YbwdyI5qlQ",
    "scope": "READ",
    "token_type": "Bearer",
    "expires_in": 119
}

# Configurations via application.yml
Header name to be used to pass login-id
config:
  authserver:
    header:
      login-id: X_LOGIN_ID

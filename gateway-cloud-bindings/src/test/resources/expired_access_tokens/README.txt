To obtain access token responses, the following can be performed:

1. kinit as a valid user

  # kinit jsmith
  Password for jsmith@EXAMPLE.COM:


2. Obtain a Knox delegation token from IDBroker

  # curl -k --negotiate -u: -X GET https://idbroker.example.com:8443/gateway/dt/knoxtoken/api/v1/token
  {"access_token":"eyJhb...m9tym","endpoint_public_cert":"MIIE0...wzAdM","token_type":"Bearer","expires_in":1559073272053}


3. Copy the access token value into an environment variable (to help make things easier)

  export CONTRIBUTOR_DT="eyJhb...m9tym"


4. Obtain cloud credentials from IDBroker using the Knox delegation token

  # curl -k --negotiate -u: -H "Authorization: Bearer $CONTRIBUTOR_DT"  https://idbroker.example.com:8443/gateway/cloud-cab/cab/api/v1/credentials
  {...}


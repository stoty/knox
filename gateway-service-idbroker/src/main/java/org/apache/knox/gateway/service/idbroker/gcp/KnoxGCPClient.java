/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.service.idbroker.gcp;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.service.idbroker.AbstractKnoxCloudCredentialsClient;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.util.JsonUtils;
import org.apache.shiro.codec.Base64;

import javax.ws.rs.core.MediaType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


public class KnoxGCPClient extends AbstractKnoxCloudCredentialsClient {

  private static final String NAME = "GCP";

  private static final String KEY_ID_ALIAS     = "gcp.credential.key";
  private static final String KEY_SECRET_ALIAS = "gcp.credential.secret";

  private static final String CONFIG_IDBROKER_SERVICE_ACCOUNT_ID = "idbroker.service.account.id";
  private static final String CONFIG_TARGET_SERVICE_ACCOUNT_ID   = "target.service.account.id";
  private static final String CONFIG_TOKEN_LIFETIME              = "token.lifetime";
  private static final String CONFIG_TOKEN_SCOPES                = "token.scopes";

  private static final String DEFAULT_TOKEN_SCOPES   = "https://www.googleapis.com/auth/cloud-platform";
  private static final String DEFAULT_TOKEN_LIFETIME = "3600s"; // default to the maximum

  private static final String SERVICE_ACCOUNTS_ENDPOINT =
                                    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/";

  private static GCPClientMessages LOG = MessagesFactory.get(GCPClientMessages.class);


  // The name of the service account representing the ID Broker
  private String idBrokerServiceAccountId = null;

  // Cache the credential, since this is not expected to change
  private GoogleCredential idBrokerCredential = null;


  @Override
  public String getName() {
    return NAME;
  }


  @Override
  public Object getCredentials() {
    return getCredentialsForRole(getRole());
  }

  @Override
  public Object getCredentialsForRole(String role) {
    return generateAccessToken(getConfigProvider().getConfig(), role);
  }


  private GoogleCredential getIDBrokerCredential(CloudClientConfiguration config) {
    String configuredServiceAccount = (String) config.getProperty(CONFIG_IDBROKER_SERVICE_ACCOUNT_ID);
    LOG.configuredServiceAccount(configuredServiceAccount);

    if (idBrokerCredential == null || !idBrokerServiceAccountId.equals(configuredServiceAccount)) {
      idBrokerServiceAccountId = configuredServiceAccount;

      Collection<String> scopes = Collections.singletonList("https://www.googleapis.com/auth/cloud-platform");

      LOG.authenticateCAB();
      try {
        idBrokerCredential = new GoogleCredential.Builder().setTransport(new NetHttpTransport())
                                                           .setJsonFactory(new JacksonFactory())
                                                           .setServiceAccountId(configuredServiceAccount)
                                                           .setServiceAccountPrivateKeyId(getKeyID())
                                                           .setServiceAccountPrivateKey(getPrivateKey())
                                                           .setServiceAccountScopes(scopes)
                                                 .build();
        // Initialize the access token
        idBrokerCredential.refreshToken();

        LOG.cabAuthenticated();
      } catch (Exception e) {
        LOG.logException(e); // TODO: PJZ: Handle this more appropriately
      }
    }

    return idBrokerCredential;
  }


  /**
   * Content-type: application/json
   * Authorization: Bearer XXXXXXXXXX
   * POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA@PROJECT.iam.gserviceaccount.com:generateAccessToken
   * {
   *   "delegates": [],
   *   "scope": [
   *     "https://www.googleapis.com/auth/cloud-platform"
   *   ],
   *   "lifetime": "3600s" // max value, and the default
   * }
   *
   * @return The GCP-specific token generation response
   *
   * {
   *   "accessToken": "YYYYYYYYYYY",
   *   "expireTime": "2018-08-22T17:13:55Z"
   * }
   */
  private String generateAccessToken(CloudClientConfiguration config, String serviceAccount) {
    String response = null;

    CloseableHttpClient http = HttpClientBuilder.create().build();

    String tokenScopes = (String) config.getProperty(CONFIG_TOKEN_SCOPES);
    if (tokenScopes == null || tokenScopes.isEmpty()) {
      tokenScopes = DEFAULT_TOKEN_SCOPES;
    }

    String[] scopes = tokenScopes.split(",");

    String tokenLifetime = (String) config.getProperty(CONFIG_TOKEN_LIFETIME);
    if (tokenLifetime == null || tokenLifetime.isEmpty()) {
      tokenLifetime = DEFAULT_TOKEN_LIFETIME;
    }

    String targetServiceAccount =
                serviceAccount != null ? serviceAccount : (String) config.getProperty(CONFIG_TARGET_SERVICE_ACCOUNT_ID);
    String url = SERVICE_ACCOUNTS_ENDPOINT + targetServiceAccount + ":generateAccessToken";

    HttpPost request = new HttpPost(url);

    GoogleCredential idBrokerCredential = getIDBrokerCredential(config);

    if (idBrokerCredential == null) {
      throw new RuntimeException("Unable to authenticate the Cloud Access Broker.");
    }

    // If the ID Broker token has expired, refresh it before trying to use it
    if (idBrokerCredential.getExpirationTimeMilliseconds() < System.currentTimeMillis()) { // TODO: PJZ: Is this a good test?
      try {
        idBrokerCredential.refreshToken();
      } catch (IOException e) {
        LOG.logException(e);
      }
    }

    String authToken = idBrokerCredential.getAccessToken();
    if (authToken != null) {
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + authToken);
    } else {
      LOG.failedToAcquireAuthTokenForCAB();
      throw new RuntimeException("Failed to acquire token for the Cloud Access Broker.");
    }

    // Create the API request payload
    Map<String, Object> jsonModel = new HashMap<>();
    jsonModel.put("delegates", Collections.emptyList());
    jsonModel.put("scope", Arrays.asList(scopes));
    jsonModel.put("lifetime", tokenLifetime);
    String jsonString = JsonUtils.renderAsJsonString(jsonModel);
    request.setEntity(new StringEntity(jsonString, StandardCharsets.UTF_8));
    request.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);

    try {
      CloseableHttpResponse httpResponse = http.execute(request);
      if (HttpStatus.SC_OK == httpResponse.getStatusLine().getStatusCode()) {
        HttpEntity entity = httpResponse.getEntity();
        if (entity != null) {
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          entity.writeTo(baos);
          response = baos.toString(StandardCharsets.UTF_8.name());
        }
      } else {
        System.out.println(httpResponse.getStatusLine().getStatusCode());
        HttpEntity entity = httpResponse.getEntity();
        if (entity != null) {
          entity.writeTo(System.out);
        }
      }
    } catch (IOException e) {
      LOG.logException(e);
    }

    return response;
  }


  private String getKeyID() {
    String keyId = null;

    try {
      char[] value = aliasService.getPasswordFromAliasForCluster(topologyName, KEY_ID_ALIAS);
      keyId = new String(value);
    } catch (AliasServiceException e) {
      LOG.logException(e);
    }

    return keyId;
  }


  private char[] getKeySecret() {
    char[] secret = null;

    try {
      secret = aliasService.getPasswordFromAliasForCluster(topologyName, KEY_SECRET_ALIAS);
    } catch (AliasServiceException e) {
      LOG.logException(e);
    }

    return secret;
  }


  private PrivateKey getPrivateKey() throws Exception {
    // Get the private key, replace any '\''n' combinations with newline chars, and convert it to a byte array
    byte[] encoded = StandardCharsets.US_ASCII.encode(CharBuffer.wrap(replaceNewlineChars(getKeySecret()))).array();
    return (KeyFactory.getInstance("RSA")).generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(encoded)));
  }


  /**
   * Replace any '\''n' character combinations with actual newline ('\n') chars from the specified char array.
   *
   * @param source A char array, which may include newline characters.
   *
   * @return The private key characters less any newline characters
   */
  private static char[] replaceNewlineChars(final char[] source) {
    char[] stripped = new char[source.length];

    int strippedCount = 0;

    for (int i = 0 ; i < source.length ; i++) {
      char c = source[i];

      if (c == '\\' && source[i+1] == 'n') {
        i++; // skip the char combination '\\n'
        stripped[strippedCount++] = '\n';
      } else if (c != '\n'){
        stripped[strippedCount++] = c;
      }
    }

    // If there were no newline chars, then just return the source, skipping the array copy
    return ((strippedCount == source.length ) ? source : Arrays.copyOfRange(stripped, 0, strippedCount));
  }


}

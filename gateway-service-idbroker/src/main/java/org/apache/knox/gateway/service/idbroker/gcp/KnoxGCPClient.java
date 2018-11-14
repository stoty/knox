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
import org.apache.commons.lang.SerializationUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.service.idbroker.AbstractKnoxCloudCredentialsClient;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerResource;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.EncryptionResult;
import org.apache.knox.gateway.util.JsonUtils;
import org.apache.shiro.codec.Base64;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

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

  private long expirationOffset = 30000;

  private String tokenLifetime = null;

  // The name of the service account representing the ID Broker
  private String idBrokerServiceAccountId = null;

  // Cache the credential, since this is not expected to change
  private GoogleCredential idBrokerCredential = null;


  @Override
  public void init(Properties context) {
    super.init(context);

    idBrokerServiceAccountId = context.getProperty(CONFIG_IDBROKER_SERVICE_ACCOUNT_ID);
    if (idBrokerServiceAccountId == null || idBrokerServiceAccountId.isEmpty()) {
      throw new IllegalArgumentException("Missing or invalid cloud access broker configuration property: " + CONFIG_IDBROKER_SERVICE_ACCOUNT_ID);
    }

    tokenLifetime = context.getProperty(CONFIG_TOKEN_LIFETIME);
    if (tokenLifetime == null || tokenLifetime.isEmpty()) {
      tokenLifetime = DEFAULT_TOKEN_LIFETIME;
    }
  }

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
    return getCachedAccessToken(role);
  }

  /**
   * Store the credentials encrypted in cache
   * @param role
   * @return
   */
  private Object getCachedAccessToken(final String role) {
    Object result;
    try {
      /**
       * Get the credentials from cache, if the credentials are not in cache use the function to load the cache.
       * Credentials are encrypted and cached
       **/
      final EncryptionResult encrypted = credentialCache.get(role, () -> {
        /* encrypt credentials and cache them */
        return cryptoService.encryptForCluster(topologyName,
                                               IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS,
                                               SerializationUtils.serialize(generateAccessToken(getConfigProvider().getConfig(), role)));
      });

      /* decrypt the credentials from cache */
      byte[] serialized = cryptoService.decryptForCluster(topologyName, IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS, encrypted.cipher, encrypted.iv, encrypted.salt);
      result = SerializationUtils.deserialize(serialized);
    } catch (final ExecutionException e) {
      LOG.cacheException(role, e.toString());
      throw new RuntimeException(e);
    }
    return result;
  }


  private GoogleCredential getIDBrokerCredential(CloudClientConfiguration config) {
    if (idBrokerCredential == null) {

      LOG.configuredServiceAccount(idBrokerServiceAccountId);
      Collection<String> scopes = Collections.singletonList("https://www.googleapis.com/auth/cloud-platform");

      LOG.authenticateCAB();

      PrivateKey pk = getPrivateKey();
      if (pk == null) {
        LOG.configError("Missing required credential alias: " + KEY_SECRET_ALIAS);
      }

      if (pk != null) {
        try {
          idBrokerCredential = new GoogleCredential.Builder().setTransport(new NetHttpTransport())
                                                             .setJsonFactory(new JacksonFactory())
                                                             .setServiceAccountId(idBrokerServiceAccountId)
//                                                             .setServiceAccountPrivateKeyId(keyID)
                                                             .setServiceAccountPrivateKey(pk)
                                                             .setServiceAccountScopes(scopes)
                                                             .build();
          // Initialize the access token
          idBrokerCredential.refreshToken();

          LOG.cabAuthenticated();
        } catch (Exception e) {
          LOG.exception(e); // TODO: PJZ: Handle this more appropriately
        }
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

    String targetServiceAccount =
                serviceAccount != null ? serviceAccount : (String) config.getProperty(CONFIG_TARGET_SERVICE_ACCOUNT_ID);
    String url = SERVICE_ACCOUNTS_ENDPOINT + targetServiceAccount + ":generateAccessToken";

    HttpPost request = new HttpPost(url);

    GoogleCredential idBrokerCredential = getIDBrokerCredential(config);
    if (idBrokerCredential == null) {
      throw new RuntimeException("Unable to authenticate the Cloud Access Broker.");
    }

    // If the ID Broker token has expired, or will soon expire, refresh it before trying to use it
    if ((idBrokerCredential.getExpirationTimeMilliseconds() - expirationOffset) < System.currentTimeMillis()) {
      try {
        idBrokerCredential.refreshToken();
      } catch (IOException e) {
        LOG.exception(e);
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
          response = EntityUtils.toString(entity, StandardCharsets.UTF_8);
        }
      } else {
        LOG.remoteErrorResponseStatus(httpResponse.getStatusLine().getStatusCode());
        HttpEntity entity = httpResponse.getEntity();
        if (entity != null) {
          LOG.remoteErrorResponse(EntityUtils.toString(entity, StandardCharsets.UTF_8));
        }
      }
    } catch (IOException e) {
      LOG.exception(e);
    }

    return response;
  }


  private String getKeyID() {
    String keyId = null;

    try {
      char[] value = aliasService.getPasswordFromAliasForCluster(topologyName, KEY_ID_ALIAS);
      if (value != null) {
        keyId = new String(value);
      }
    } catch (AliasServiceException e) {
      LOG.exception(e);
    }

    return keyId;
  }


  private char[] getKeySecret() {
    char[] secret = null;

    try {
      secret = aliasService.getPasswordFromAliasForCluster(topologyName, KEY_SECRET_ALIAS);
    } catch (AliasServiceException e) {
      LOG.exception(e);
    }

    return secret;
  }


  private PrivateKey getPrivateKey() {
    PrivateKey result = null;

    // Get the private key, replace any '\''n' combinations with newline chars, and convert it to a byte array
    char[] secret = getKeySecret();
    if (secret != null && secret.length > 0) {
      byte[] encoded = StandardCharsets.US_ASCII.encode(CharBuffer.wrap(replaceNewlineChars(secret))).array();
      try {
        result = (KeyFactory.getInstance("RSA")).generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(encoded)));
      } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
        LOG.exception(e);
      }
    }

    return result;
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

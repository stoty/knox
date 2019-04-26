/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.service.idbroker.azure;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.AzureEnvironment;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.service.idbroker.AbstractKnoxCloudCredentialsClient;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerConfigException;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerResource;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.EncryptionResult;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class KnoxAzureClient extends AbstractKnoxCloudCredentialsClient {

  private static final String NAME = "ADLS2";

  private static final String CLIENT_ID = "azure.adls2.credential.%s.clientid";
  private static final String CLIENT_SECRET = "azure.adls2.credential.%s.secret";
  private static final String TENANT_NAME = "azure.adls2.tenantname";
  private static final String RESOURCE_NAME = "azure.adls2.resource";
  private static final String MSI_CREDENTIALS = "azure.adls2.credentials.msi";
  private static final String DEFAULT_RESOURCE_NAME = "https://storage.azure.com/";
  private static final ExecutorService executorService = Executors
      .newFixedThreadPool(10);
  private static AzureClientMessages LOG = MessagesFactory
      .get(AzureClientMessages.class);
  private final ObjectWriter mapper = new ObjectMapper().writer()
      .withDefaultPrettyPrinter();

  @Override
  public void init(Properties context) {
    super.init(context);
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
   *
   * @param role
   * @return
   */
  private Object getCachedAccessToken(final String role) {
    Object result;
    try {
      final EncryptionResult encrypted = credentialCache.get(role, () -> {
        /* encrypt credentials and cache them */
        return cryptoService.encryptForCluster(topologyName,
            IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS, SerializationUtils
                .serialize(generateAccessToken(getConfigProvider().getConfig(),
                    role)));
      });

      /* decrypt the credentials from cache */
      byte[] serialized = cryptoService.decryptForCluster(topologyName,
          IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS, encrypted.cipher,
          encrypted.iv, encrypted.salt);
      result = SerializationUtils.deserialize(serialized);
    } catch (final ExecutionException e) {
      LOG.cacheException(role, e.toString());
      throw new RuntimeException(e);
    }
    return result;
  }

  /**
   * For each ROLE we have a service account.
   *
   * @param config
   * @param role
   * @return
   */
  private String generateAccessToken(final CloudClientConfiguration config,
      final String role) {

    /* check if we can access MSI */
    final boolean isMSI = config.getProperty(MSI_CREDENTIALS) != null && Boolean
        .parseBoolean((String) config.getProperty(MSI_CREDENTIALS));

    try {
      /* if running inside the Azure VM and MSI identity is configured */
      if (isMSI) {
        return getAccessTokenUsingMSI(role);
      }
      /* non - MSI */
      else {
        return getAccessTokenUsingServicePrincipal(config, role);
      }

    } catch (final Exception e) {
      LOG.accessTokenGenerationError(e.toString());
      throw new RuntimeException(e);
    }

  }

  /**
   * Get the access token for a given clientId (role) using Azure user assigned
   * managed identity.
   *
   * @param clientId
   * @return access token
   * @throws IOException
   */
  private String getAccessTokenUsingMSI(final String clientId)
      throws IOException {

    KnoxMSICredentials credentials = new KnoxMSICredentials(
        AzureEnvironment.AZURE);

    /* user assigned MSI initialize it, else use system assigned MSI */
    if (clientId != null) {
      credentials = credentials.withClientId(clientId);
    }

    /* return the MSI access token */
    return credentials.getToken(DEFAULT_RESOURCE_NAME);
  }

  /**
   * Get the access token for a given role using pre-configured service
   * principal.
   *
   * @param config CloudClientConfiguration
   * @param role   role for which access token is needed
   * @return
   * @throws MalformedURLException
   * @throws ExecutionException
   * @throws InterruptedException
   * @throws JsonProcessingException
   */
  private String getAccessTokenUsingServicePrincipal(
      final CloudClientConfiguration config, final String role)
      throws MalformedURLException, ExecutionException, InterruptedException,
      JsonProcessingException {

    final String tenantName = (String) config.getProperty(TENANT_NAME);
    if (tenantName == null || tenantName.isEmpty()) {
      LOG.configError(String.format(
          "Missing required tenant name, please configure it using the property %s",
          TENANT_NAME));
      throw new RuntimeException(String.format(
          "Missing required tenant name, please configure it using the property %s",
          TENANT_NAME));
    }

    String resourceName = (String) config.getProperty(RESOURCE_NAME);
    if (resourceName == null || resourceName.isEmpty()) {
      resourceName = DEFAULT_RESOURCE_NAME;
    }

    final AuthenticationContext authContext = new AuthenticationContext(
        String.format("https://login.microsoftonline.com/%s/", tenantName),
        true, executorService);
    AuthenticationResult result;

    final ClientCredential credentials = new ClientCredential(
        getAliasValue(String.format(CLIENT_ID, role)),
        getAliasValue(String.format(CLIENT_SECRET, role)));
    final Future<AuthenticationResult> future = authContext
        .acquireToken(resourceName, credentials, null);
    result = future.get();

    if (result != null && result.getAccessToken() != null) {
      final AzureToken token = new AzureToken(result.getAccessTokenType(),
          result.getAccessToken(),
          Long.toString(result.getExpiresOnDate().getTime()));
      return mapper.writeValueAsString(token);

    } else {
      LOG.accessTokenGenerationError("Failed to get access token");
      return null;
    }

  }

  /**
   * Get the Alias value for a given alias.
   *
   * @param alias
   * @return
   */
  private String getAliasValue(final String alias) {
    String value = null;
    try {
      char[] val = aliasService
          .getPasswordFromAliasForCluster(topologyName, alias);
      if (val == null) {
        LOG.aliasConfigurationError(alias);
        throw new RuntimeException(new IdentityBrokerConfigException(String
            .format("Missing alias: %s, required for Cloud Access Broker",
                alias)));
      } else {
        value = new String(val);
      }
    } catch (AliasServiceException e) {
      LOG.exception(e);
    }
    return value;
  }

  /**
   * Token response from Azure
   */
  public class AzureToken {

    private final ObjectWriter mapper = new ObjectMapper().writer()
        .withDefaultPrettyPrinter();

    @JsonProperty(value = "token_type")
    private String tokenType;
    @JsonProperty(value = "access_token")
    private String accessToken;
    @JsonProperty(value = "expires_on")
    private String expiresOn;

    public AzureToken(final String tokenType, final String accessToken,
        final String expiresOn) {
      this.tokenType = tokenType;
      this.accessToken = accessToken;
      this.expiresOn = expiresOn;
    }

  }

}

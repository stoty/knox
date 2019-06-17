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
import com.google.gson.Gson;
import com.jayway.jsonpath.JsonPath;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.AzureEnvironment;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.service.idbroker.AbstractKnoxCloudCredentialsClient;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerConfigException;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerResource;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.EncryptionResult;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
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
  private static final String SYSTEM_MSI_RESOURCE_NAME_FORMAT = "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s";
  private static final String TOKEN_AUDIENCE_MANAGEMENT = "https://management.azure.com/";

  private static final ExecutorService executorService = Executors
      .newFixedThreadPool(10);
  private static AzureClientMessages LOG = MessagesFactory
      .get(AzureClientMessages.class);
  private final ObjectWriter mapper = new ObjectMapper().writer()
      .withDefaultPrettyPrinter();

  private String systemMSIresourceName = "";
  /**
   * List of all user assigned identities defined in a topology
   * This list is used to attach new MSIs
   */
  private Set<String> userAssignedMSIIdentities = new HashSet<>();
  private boolean areUserAssignedIdentitiesInitialized = false;

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
   * Load and cache list of MSIs defined for user and groups in topology
   * and attach them.
   *
   * @param config properties list
   */
  private void loadUserIdentities(final CloudClientConfiguration config) {

    userAssignedMSIIdentities = config.getAllRoles();
    /* add the identities to VM */
    addIdentitiesToVM(userAssignedMSIIdentities);
    areUserAssignedIdentitiesInitialized = true;
    LOG.foundUserMSI(userAssignedMSIIdentities.size(), this.topologyName);
  }

  /**
   * Function to assign user defined identities to Azure VM. Function takes
   * identity list as input. NOTE: identity list should contains ALL identities
   * (new and old)
   *
   * @param identities identity list
   * @return
   */
  private String addIdentitiesToVM(final Set<String> identities) {

    final KnoxMSICredentials credentials = new KnoxMSICredentials(
        AzureEnvironment.AZURE);

    String accessToken;
    /* return the MSI access token */
    try {
      accessToken = credentials.getToken(TOKEN_AUDIENCE_MANAGEMENT);
    } catch (final Exception e) {
      LOG.accessTokenGenerationError(e.toString());
      throw new RuntimeException(e);
    }

    /* create json payload */
    final MSIPayload.Identity id = new MSIPayload.Identity("SystemAssigned, UserAssigned");

    for (final String identity : identities) {
      id.addProp(identity, new Object());
    }

    final MSIPayload payload = new MSIPayload(id);

    final Gson gson = new Gson();
    final String json = gson.toJson(payload);

    try {
      final String response = credentials
          .attachIdentities(getSystemMSIResourceName(credentials),
              json, accessToken);
      LOG.attachIdentitiesSuccess(identities.toString());
      return response;
    } catch (Exception e) {
      LOG.attachIdentitiesError(e.toString());
      throw new RuntimeException(e);
    }
  }

  /**
   * This function gets the system MSI resource name and cache it locally.
   */
  private String getSystemMSIResourceName(final KnoxMSICredentials credentials)
      throws InterruptedException {
    /* cache the system MSI resource name it's not changing */
    if (StringUtils.isBlank(systemMSIresourceName)) {
      final String computeMetaData = credentials
          .getComputeInstanceMetadata(null);

      systemMSIresourceName = String
          .format(Locale.ROOT, SYSTEM_MSI_RESOURCE_NAME_FORMAT,
              JsonPath.read(computeMetaData, "$.subscriptionId"),
              JsonPath.read(computeMetaData, "$.resourceGroupName"),
              JsonPath.read(computeMetaData, "$.name"));
    }
    LOG.printSystemMSIResourceName(systemMSIresourceName);
    return systemMSIresourceName;
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
        .parseBoolean(config.getProperty(MSI_CREDENTIALS));

    try {
      /* if running inside the Azure VM and MSI identity is configured */
      if (isMSI) {
        return getAccessTokenUsingMSI(config, role);
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
   * Get the access token for a given MSI Resource ID (role) using Azure user
   * assigned managed identity.
   * <p>
   * User MSIs are not expected to be attached to VM, so IDBroker will
   * explicitly attach them to the VM. if the identity is not attached, IDBroker
   * will attach it.
   *
   * @param resourceID MSI Resource ID
   * @return access token
   * @throws IOException
   */
  private String getAccessTokenUsingMSI(final CloudClientConfiguration config, final String resourceID)
      throws IOException {
    KnoxMSICredentials credentials = new KnoxMSICredentials(
        AzureEnvironment.AZURE);

    if (!areUserAssignedIdentitiesInitialized) {
      loadUserIdentities(config);
    }

    /* check if this identity is already attached, if not attach it */
    if (!userAssignedMSIIdentities.contains(resourceID)) {
      userAssignedMSIIdentities.add(resourceID);
      addIdentitiesToVM(userAssignedMSIIdentities);
    }

    /* user assigned MSI initialize it, else use system assigned MSI */
    if (resourceID != null) {
      credentials = credentials.withIdentityId(resourceID);
    } else {
      /* Use system MSI, normally this will not work, but IDBroker VM MSI
      * can be configured with storage permissions, Bug or Feature ? */
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
      LOG.configError(String.format(Locale.ROOT,
          "Missing required tenant name, please configure it using the property %s",
          TENANT_NAME));
      throw new RuntimeException(String.format(Locale.ROOT,
          "Missing required tenant name, please configure it using the property %s",
          TENANT_NAME));
    }

    String resourceName = (String) config.getProperty(RESOURCE_NAME);
    if (resourceName == null || resourceName.isEmpty()) {
      resourceName = DEFAULT_RESOURCE_NAME;
    }

    final AuthenticationContext authContext = new AuthenticationContext(
        String.format(Locale.ROOT,"https://login.microsoftonline.com/%s/", tenantName),
        true, executorService);
    AuthenticationResult result;

    final ClientCredential credentials = new ClientCredential(
        getAliasValue(String.format(Locale.ROOT, CLIENT_ID, role)),
        getAliasValue(String.format(Locale.ROOT, CLIENT_SECRET, role)));
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
            .format(Locale.ROOT, "Missing alias: %s, required for Cloud Access Broker",
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

  /**
   * Format to send request to Azure
   */
  static class MSIPayload {

    private Identity identity;

    public MSIPayload(final Identity id) {
      this.identity = id;
    }

    static class Identity {
      private String type;
      Map<String, Object> UserAssignedIdentities = new HashMap<>();
      public Identity(final String type) {
        super();
        this.type = type;
      }
      public void addProp(final String key, final Object obj) {
        UserAssignedIdentities.put(key, obj);
      }
    }
  }

}

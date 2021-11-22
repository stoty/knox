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
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.service.idbroker.AbstractKnoxCloudCredentialsClient;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerConfigException;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerResource;
import org.apache.knox.gateway.service.idbroker.ResponseUtils;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.EncryptionResult;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.MalformedURLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
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
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class KnoxAzureClient extends AbstractKnoxCloudCredentialsClient {
  private static final String NAME = "ADLS2";

  private static final String CLIENT_ID = "azure.adls2.credential.%s.clientid";
  private static final String CLIENT_SECRET = "azure.adls2.credential.%s.secret";
  private static final String TENANT_NAME = "azure.adls2.tenantname";
  private static final String RESOURCE_NAME = "azure.adls2.resource";

  /* retry count for checking attached uaMSIs */
  private static final String AZURE_INITIAL_REQUEST_RETRY_COUNT = "azure.initial.request.retry.count";
  private static final String ASSUMER_IDENTITY = "azure.vm.assumer.identity";
  private static final String AZURE_RETRY_DELAY = "azure.retry.delay";
  private static final int AZURE_INITIAL_REQUEST_RETRY_DEFAULT = 5;
  private static final int AZURE_RETRY_DELAY_DEFAULT = 5;

  /* property to account for clock skew */
  private static final String AZURE_TOKEN_SKEW_OFFSET = "azure.token.skew.offset";
  /* default value in seconds */
  private static final int AZURE_TOKEN_SKEW_OFFSET_DEFAULT = 120;

  private static final String DEFAULT_RESOURCE_NAME = "https://storage.azure.com/";
  private static final String SYSTEM_MSI_RESOURCE_NAME_FORMAT = "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s";
  private static final String TOKEN_AUDIENCE_MANAGEMENT = "https://management.azure.com/";
  private static final ExecutorService executorService = Executors
      .newFixedThreadPool(10);
  private static final AzureClientMessages LOG = MessagesFactory.get(AzureClientMessages.class);
  private final ObjectWriter mapper = new ObjectMapper().writer()
      .withDefaultPrettyPrinter();

  public static final String MSI_PATH_REGEX_NAMED = "\\/?subscriptions\\/(?<subscription>.*?)\\/resource[gG]roups\\/(?<resourceGroup>.*?)\\/providers\\/Microsoft\\.ManagedIdentity\\/userAssignedIdentities\\/(?<vmName>.*?)$";
  public static final Pattern MSI_PATH_PATTERN = Pattern
      .compile(MSI_PATH_REGEX_NAMED);

  private String systemMSIResourceName = "";
  /**
   * List of all user assigned identities defined in a topology
   * This list is used to attach new MSIs
   */
  private Set<String> userAssignedMSIIdentities = new HashSet<>();
  private boolean areUserAssignedIdentitiesInitialized;

  /**
   * List of all user assigned identities that are attached to the VM.
   */
  private Set<String> retrievedUserIdentities;

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
    String accessToken = null;
    try {
      accessToken = (String) getCachedAccessToken(role);
      /* Check if we are getting expired token from the cache, if so retry
       * until the configured clock skew time is reached. */
      int skew = Integer.parseInt(getConfigProvider().getConfig()
          .getProperty(AZURE_TOKEN_SKEW_OFFSET,
              String.valueOf(AZURE_TOKEN_SKEW_OFFSET_DEFAULT)));
      int retryDelay = Integer.parseInt(getConfigProvider().getConfig()
          .getProperty(AZURE_RETRY_DELAY,
              String.valueOf(AZURE_RETRY_DELAY_DEFAULT)));

      final long skewTS =
          System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(skew);

      /* As of skewDate, Azure caches tokens server side until it is expired.
       * new token can be requested 3 mins before expiry */
      while (isTokenExpired(accessToken)
          && System.currentTimeMillis() < skewTS) {
        LOG.cacheTokenExpired(role);
        TimeUnit.SECONDS.sleep(retryDelay);
        /* try to get access token bypassing cache */
        accessToken = generateAccessToken(getConfigProvider().getConfig(),
            role);
        /* update cache with new value  */
        credentialCache.put(role, cryptoService.encryptForCluster(topologyName,
            IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS,
            SerializationUtils.serialize(accessToken)));
      }
    } catch (final InterruptedException e) {
      /* Log and move on */
      LOG.cacheTokenRetryError(role, e.toString());
    } catch (final WebApplicationException e) {
      /* rethrow already handles exceptions  */
      throw e;
    } catch (final Exception e) {
      /* All other exceptions return 403 */
      final String errorMessage = e.getMessage() != null ? e.getMessage() : e.toString();
      LOG.accessTokenGenerationError(errorMessage);
      LOG.printStackTrace(ExceptionUtils.getStackTrace(e));
      String responseEntity =
              ResponseUtils.createErrorResponseJSON("Error obtaining access token", errorMessage);
      final Response response =
              KnoxMSICredentials.errorResponseWrapper(Response.Status.FORBIDDEN, responseEntity);
      throw new WebApplicationException(response);
    }
    return accessToken;
  }

  /**
   * Load and cache list of MSIs defined for user and groups in topology
   * and attach them.
   *
   * @param config properties list
   */
  private void loadUserIdentities(final CloudClientConfiguration config) {

    userAssignedMSIIdentities = config.getAllRoles();
    if(!StringUtils.isBlank(config.getProperty(ASSUMER_IDENTITY))) {
      userAssignedMSIIdentities.add(config.getProperty(ASSUMER_IDENTITY));
    }
    /* add the identities to VM */
    addIdentitiesToVM(config, userAssignedMSIIdentities);
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
  private void addIdentitiesToVM(final CloudClientConfiguration config, final Set<String> identities) {

    final KnoxMSICredentials credentials = new KnoxMSICredentials(
        AzureEnvironment.AZURE, aliasService);

    /* use assumer identity to get access tokens for MSI attachment */
    final String assumerIdentity = config.getProperty(ASSUMER_IDENTITY);
    if (!StringUtils.isBlank(assumerIdentity)) {
      final Matcher matcher = MSI_PATH_PATTERN.matcher(assumerIdentity);
      if (matcher.matches()) {
        credentials.withIdentityId(assumerIdentity);
      } else {
        /* assumer id is not configured properly,
        falling back on System MSI which could
        result in an error if the VM does not have proper permissions */
        LOG.invalidAssumerMSI(assumerIdentity);
      }
    } else {
      /* assumer id is not set,
        falling back on System MSI which could
        result in an error if the VM does not proper permissions */
      LOG.noAssumerIdentityConfigured();
    }

    String accessToken;
    try {
      accessToken = JsonPath.read(credentials.getToken(TOKEN_AUDIENCE_MANAGEMENT), "$.access_token");
    } catch (final Exception e) {
      LOG.accessTokenGenerationError(e.toString());
      throw new RuntimeException(e);
    }

    try {
      /* attach identities only if they are not already attached */
      if (!areIdentitiesAttached(credentials, accessToken, identities)) {
        /* create json payload */
        final MSIPayload.Identity id = new MSIPayload.Identity(
            "UserAssigned");

        for (final String identity : identities) {
          /* check if this role is MSI */
          final Matcher matcher = MSI_PATH_PATTERN.matcher(identity);
          if (matcher.matches()) {
            id.addProp(identity, new Object());
          } else {
            LOG.notValidMSISkipAttachment(identity);
          }
        }

        final MSIPayload payload = new MSIPayload(id);
        final Gson gson = new Gson();
        final String json = gson.toJson(payload);

        /* before we attach new identities, get new tokens for existing identities */
        forceUpdateAllCachedAccessToken();

        credentials
            .attachIdentities(getSystemMSIResourceName(credentials), json,
                accessToken);
        LOG.attachIdentitiesSuccess(identities.toString());

        /* check if the identities are attached, There will be some delay for the identity to get attached. */
        int count = 0;
        int retryCount = Integer.parseInt(config
            .getProperty(AZURE_INITIAL_REQUEST_RETRY_COUNT,
                String.valueOf(AZURE_INITIAL_REQUEST_RETRY_DEFAULT)));
        int retryDelay = Integer.parseInt(config.getProperty(AZURE_RETRY_DELAY,
            String.valueOf(AZURE_RETRY_DELAY_DEFAULT)));

        while (count <= retryCount) {
          /* log if we are unsuccessful */
          if(count == retryCount) {
            LOG.attachIdentitiesFailure();
            break;
          }
          /* Check if all the identities are attached to the VM, if so break else wait and try again */
          if (areIdentitiesAttached(credentials, accessToken, identities)) {
            break;
          }

          LOG.retryCheckAssignedMSI(count);
          count++;
          TimeUnit.SECONDS.sleep(retryDelay);
        }
      } else {
        /* identities already attached nothing to do */
        LOG.identitiesAlreadyAttached();
      }
    } catch (Exception e) {
      LOG.attachIdentitiesError(e.toString());
      throw new RuntimeException(e);
    }
  }

  /**
   * A function to test whether all the identities are attached to the IDB VM.
   * @param credentials
   * @param accessToken
   * @param localIdentities
   * @return
   * @throws InterruptedException
   */
  private boolean areIdentitiesAttached(final KnoxMSICredentials credentials,
      final String accessToken, final Set<String> localIdentities)
      throws InterruptedException {
    retrievedUserIdentities = credentials
        .getAssignedUserIdentityList(getSystemMSIResourceName(credentials),
            accessToken);
    /* Check if all the identities are attached to the VM */
    if (retrievedUserIdentities.containsAll(localIdentities)) {
      LOG.retrievedIdentityListMatches(retrievedUserIdentities.size());
      return true;
    } else {
      LOG.retrievedIdentityListNoMatches(retrievedUserIdentities.size(), localIdentities.size());
    }
    return false;
  }

  /**
   * This function gets the system MSI resource name and cache it locally.
   */
  private String getSystemMSIResourceName(final KnoxMSICredentials credentials)
      throws InterruptedException {
    /* cache the system MSI resource name it's not changing */
    if (StringUtils.isBlank(systemMSIResourceName)) {
      final String computeMetaData = credentials
          .getComputeInstanceMetadata(null);

      systemMSIResourceName = String
          .format(Locale.ROOT, SYSTEM_MSI_RESOURCE_NAME_FORMAT,
              JsonPath.read(computeMetaData, "$.subscriptionId"),
              JsonPath.read(computeMetaData, "$.resourceGroupName"),
              JsonPath.read(computeMetaData, "$.name"));
    }
    LOG.printSystemMSIResourceName(systemMSIResourceName);
    return systemMSIResourceName;
  }

  /**
   * Store the credentials encrypted in cache
   *
   * @param role
   * @return
   */
  protected Object getCachedAccessToken(final String role) {
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
   * This method force updates all cached access tokens for mapped MSIs. This is
   * done to update the TTL of tokens before an anticipated long running
   * operation such as a ne wMSI attachment. This will ONLY come into play when
   * new mappings are added.
   */
  private void forceUpdateAllCachedAccessToken() throws IOException {

    /* If identities are not initialized (attached) can't get access token */
    if(!areUserAssignedIdentitiesInitialized) {
      return;
    }

    KnoxMSICredentials credentials = new KnoxMSICredentials(
        AzureEnvironment.AZURE, aliasService);
    if(userAssignedMSIIdentities.size() > 1) {
      LOG.forceUpdateCachedTokens(userAssignedMSIIdentities.toString());
    }
    for (String resourceID : userAssignedMSIIdentities) {
      /* Only get tokens for attached identities, no point trying and failing to get tokens for non-attached identities */
      if (retrievedUserIdentities != null && retrievedUserIdentities
          .contains(resourceID)) {
        credentials = credentials.withIdentityId(resourceID);
        credentialCache.put(resourceID, cryptoService
            .encryptForCluster(topologyName,
                IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS,
                SerializationUtils
                    .serialize(credentials.getToken(DEFAULT_RESOURCE_NAME))));
      }
    }
  }

  /**
   * For each ROLE we have a service account.<p/>
   * <b>Assumption:</b> If we detect MSI format we try to use MSI to get access
   * tokens
   * else we use service principal configured with alias service.
   *
   * @param config
   * @param role
   * @return
   */
   protected String generateAccessToken(final CloudClientConfiguration config,
      final String role) {
    /* check if this role is MSI */
    final Matcher matcher = MSI_PATH_PATTERN.matcher(role);
    try {
      /* if running inside the Azure VM and MSI identity is configured */
      if (matcher.matches()) {
        LOG.usingMSIResource(role);
        return getAccessTokenUsingMSI(config, role);
      }
      /* non - MSI */
      else {
        LOG.usingPrincipalResource(role);
        return getAccessTokenUsingServicePrincipal(config, role);
      }

    } catch (final Exception e) {
      LOG.accessTokenGenerationError(e.toString());
      throw new RuntimeException(e);
    }
  }

  /**
   * Checks token expiry.
   * use expires_on value over expires_in.
   * @return Returns true if token is expired else returns false.
   */
  private boolean isTokenExpired(final String accessToken) {

    long expiryTS;
    /*
     * If expires_on is set, use it over expires_in value.  If neither
     * are set, assume token is expired.
     */
    if(!StringUtils.isBlank(JsonPath.read(accessToken, "$.expires_on"))) {
      expiryTS = Long.parseLong(JsonPath.read(accessToken, "$.expires_on"));
    } else if (!StringUtils.isBlank(JsonPath.read(accessToken, "$.expires_in")) ) {
      String expiresIn = JsonPath.read(accessToken, "$.expires_in");
      Instant instant = Instant.now().plus(Long.parseLong(expiresIn), ChronoUnit.SECONDS);
      expiryTS = instant.getEpochSecond();
    } else {
      return true;
    }

    LOG.recordTokenExpiryTime(Date.from(Instant.ofEpochSecond(expiryTS)).toString(), Date.from(Instant.now()).toString());
    return Instant.ofEpochSecond(expiryTS).isBefore(Instant.now());
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
    /* flag to mark the first run */
    boolean firstRun = false;
    KnoxMSICredentials credentials = new KnoxMSICredentials(
        AzureEnvironment.AZURE, aliasService);

    if (!areUserAssignedIdentitiesInitialized) {
      loadUserIdentities(config);
      firstRun = true;
    }

    /* check if this identity is already attached, if not attach it */
    if (!userAssignedMSIIdentities.contains(resourceID)) {
      userAssignedMSIIdentities.add(resourceID);
      addIdentitiesToVM(config, userAssignedMSIIdentities);
    }

    /* user assigned MSI initialize it, else use system assigned MSI */
    if (resourceID != null) {
      credentials = credentials.withIdentityId(resourceID);
    } else {
      /* Use system MSI, normally this will not work, but IDBroker VM MSI
      * can be configured with storage permissions, Bug or Feature ? */
    }

    /* return the MSI access token */
    if(!firstRun) {
      /* if this is not during initialization then the failure most
      likely related to something else */
      return credentials.getToken(DEFAULT_RESOURCE_NAME);
    } else {
      /* for first run, return the MSI access token retrying in case of failure */
      String accessToken = null;
      int count = 0;
      int retryCount = Integer.parseInt(config.getProperty(
          AZURE_INITIAL_REQUEST_RETRY_COUNT,
          String.valueOf(AZURE_INITIAL_REQUEST_RETRY_DEFAULT)));
      int retryDelay = Integer.parseInt(config.getProperty(AZURE_RETRY_DELAY,
          String.valueOf(AZURE_RETRY_DELAY_DEFAULT)));

      while (count < retryCount) {
        try {
          accessToken = credentials.getToken(DEFAULT_RESOURCE_NAME);
          break;
        } catch (final Exception e) {
          count++;
          LOG.failedRetryMSIaccessToken(resourceID, count);
          /* throw the last exception */
          if (count == retryCount - 1) {
            throw e;
          }
          try {
            TimeUnit.SECONDS.sleep(retryDelay);
          } catch (InterruptedException ex) {
            throw new IOException(ex);
          }
        }
      }
      return accessToken;
    }
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

    final String tenantName = config.getProperty(TENANT_NAME);
    if (tenantName == null || tenantName.isEmpty()) {
      LOG.configError(String.format(Locale.ROOT,
          "Missing required tenant name, please configure it using the property %s",
          TENANT_NAME));
      throw new RuntimeException(String.format(Locale.ROOT,
          "Missing required tenant name, please configure it using the property %s",
          TENANT_NAME));
    }

    String resourceName = config.getProperty(RESOURCE_NAME);
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

    MSIPayload(final Identity id) {
      this.identity = id;
    }

    static class Identity {
      private String type;
      Map<String, Object> UserAssignedIdentities = new HashMap<>();
      Identity(final String type) {
        super();
        this.type = type;
      }
      public void addProp(final String key, final Object obj) {
        UserAssignedIdentities.put(key, obj);
      }
    }
  }

}

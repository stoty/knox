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

package org.apache.knox.gateway.cloud.idbroker.abfs;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.oauth2.AzureADToken;
import org.apache.hadoop.fs.azurebfs.services.AuthType;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.SecretManager;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.service.AbstractService;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxToken;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxTokenMonitor;
import org.apache.knox.gateway.cloud.idbroker.common.OAuthPayload;
import org.apache.knox.gateway.cloud.idbroker.common.Preconditions;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.util.Tokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_AUTH_TYPE_PROPERTY_NAME;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_TOKEN_PROVIDER_TYPE_PROPERTY_NAME;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_DELEGATION_TOKEN_PROVIDER_TYPE;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ENABLE_DELEGATION_TOKEN;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.MESSAGE_FAILURE_TO_AUTHENTICATE_TO_IDB_DT;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.MESSAGE_FAILURE_TO_AUTHENTICATE_TO_IDB_KERBEROS;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBConstants.IDB_TOKEN_KIND;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_DT_EXPIRATION_OFFSET;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_RETRY_COUNT;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkState;

/**
 * The class which does the real integration between ABFS and IDB.
 * Independent instances are shared in both
 * {@link AbfsIDBDelegationTokenManager} and {@link AbfsIDBCredentialProvider},
 * which makes the code a bit messy.
 * <p>
 * There are essentially two instantiation paths
 * <p>
 * 1. credential provider: looks for DT credentials for the current FS,
 * and if found, uses them. If not falls back to IDBroker.
 * <p>
 * 2. DT manager. Recycles existing DT credentials if asked, else builds
 * some with the help of IDBroker.
 * <p>
 * Both are incomplete at present as we don't have IDBroker issuing any
 * Azure tokens. Instead we fallback to local OAuth secrets.
 */
class AbfsIDBIntegration extends AbstractService {

  private static final Logger LOG = LoggerFactory.getLogger(AbfsIDBIntegration.class);

  private URI fsUri;

  private Text service;

  private final Configuration configuration;

  private KnoxTokenMonitor knoxTokenMonitor;

  private final long knoxTokenExpirationOffsetSeconds;

  private final int retryCount;

  /**
   * Cached principal.
   */
  private UserGroupInformation owner;

  /**
   * Client connection, created in service start.
   */
  private AbfsIDBClient idbClient;

  /**
   * Any deployed token.
   */
  private Token<AbfsIDBTokenIdentifier> deployedToken;

  private KnoxToken knoxToken;

  private AzureADToken adToken;

  private final Lock serviceStartLock = new ReentrantLock(true);
  private final Lock getKnoxTokenLock = new ReentrantLock(true);
  private final Lock getAzureADTokenLock = new ReentrantLock(true);

  /**
   * A correlation ID.
   * If an existing DT is found, its correlation ID will be extracted and
   * used/propagated.
   */
  private String correlationId = UUID.randomUUID().toString();

  /**
   * Secret manager to use.
   */
  private static final SecretManager<AbfsIDBTokenIdentifier> secretManager = new TokenSecretManager();

  /**
   * Instantiate.
   * As well as binding the fsUri and configuration fields, the owner
   * is set to the current user.
   *
   * @param fsUri         filesystem URI
   * @param configuration filesystem configuration
   * @throws IOException failure
   */
  private AbfsIDBIntegration(@Nonnull final URI fsUri,
                             @Nonnull final Configuration configuration,
                             @Nonnull final String origin) throws IOException {

    this("AbfsIDBIntegration", fsUri, configuration, origin);
  }

  /**
   * Instantiate.
   * As well as binding the fsUri and configuration fields, the owner
   * is set to the current user.
   *
   * @param fsUri         filesystem URI
   * @param configuration filesystem configuration
   * @throws IOException failure
   */
  AbfsIDBIntegration(@Nonnull final String serviceName,
                     @Nonnull final URI fsUri,
                     @Nonnull final Configuration configuration,
                     @Nonnull final String origin)
      throws IOException {
    super(serviceName);

    this.fsUri = checkNotNull(fsUri, "Filesystem URI");
    this.configuration = checkNotNull(configuration);
    // save the DT owner
    this.owner = UserGroupInformation.getCurrentUser();

    this.service = new Text(fsUri.getScheme() + "://" + fsUri.getAuthority());

    if (LOG.isDebugEnabled() && !this.service.toString().equals(fsUri.toString())) {
      LOG.debug("Truncating service URI from {} to {} [{}]", fsUri, this.service, origin);
    }

    knoxTokenExpirationOffsetSeconds = configuration.getLong(IDBROKER_DT_EXPIRATION_OFFSET.getPropertyName(),
        Long.parseLong(IDBROKER_DT_EXPIRATION_OFFSET.getDefaultValue()));

    retryCount = configuration.getInt(IDBROKER_RETRY_COUNT.getPropertyName(),
        Integer.parseInt(IDBROKER_DT_EXPIRATION_OFFSET.getDefaultValue()));

    LOG.debug("Creating AbfsIDBIntegration:\n\tOrigin: {}\n\tService: {}\n\tOwner: {}",
              origin,
              this.service,
              this.owner.getUserName());
  }

  /**
   * Create as part of the binding process for an Azure Delegation Token manager.
   *
   * @param fsUri filesystem URI.
   * @param conf  configuration.
   * @return a started instance.
   * @throws IOException failure
   */
  static AbfsIDBIntegration fromDelegationTokenManager(
      final URI fsUri,
      final Configuration conf) throws IOException {
    AbfsIDBIntegration integration = new AbfsIDBIntegration(fsUri, conf, "DelegationTokenManager");
    integration.init(conf);
    integration.start();
    return integration;
  }

  /**
   * Create as part of the binding process of an Azure credential provider.
   *
   * @param fsUri filesystem URI.
   * @param conf  configuration.
   * @return a started instance.
   * @throws IOException failure
   */
  static AbfsIDBIntegration fromAbfsCredentialProvider(
      final URI fsUri,
      final Configuration conf) throws IOException {
    AbfsIDBIntegration integration = new AbfsIDBIntegration(fsUri, conf, "CredentialProvider");
    integration.init(conf);
    integration.start();
    return integration;
  }

  /**
   * Start the service.
   * This includes looking up for any DT of the current user.
   *
   * @throws Exception failure.
   */
  @Override
  protected void serviceStart() throws Exception {
    serviceStartLock.lock();
    try {
      LOG.debug("Starting IDB integration for ABFS filesystem {}", fsUri);

      super.serviceStart();

      idbClient = getClient();

      initKnoxTokenMonitor();

      // retrieve the DT from the owner
      deployedToken = lookupTokenFromOwner();

      if (deployedToken != null) {
        AbfsIDBTokenIdentifier id = deployedToken.decodeIdentifier();
        correlationId = id.getTrackingId();
        adToken = buildADTokenCredentials(id);
        knoxToken = buildKnoxToken(id);

        LOG.debug("Deployed for {} with token identifier {}", fsUri, id);

        monitorKnoxToken();
      }
    } finally {
      serviceStartLock.unlock();
    }
  }

  private void initKnoxTokenMonitor() {
    if (knoxTokenMonitor == null) {
      if (idbClient != null && idbClient.shouldInitKnoxTokenMonitor()) {
        knoxTokenMonitor = new KnoxTokenMonitor();
      }
    }
  }

  private void monitorKnoxToken() {
    // Maybe initialize the Knox token monitor; since the monitor was initiated at service start this is just a 2nd check to avoid NPEs for sure
    initKnoxTokenMonitor();

    // Only start monitoring the token if the token monitor has been initialized
    if (knoxTokenMonitor != null) {
      knoxTokenMonitor.monitorKnoxToken(knoxToken, knoxTokenExpirationOffsetSeconds, new GetKnoxTokenCommand());
    }
  }

  private void stopKnoxTokenMonitor() {
    if (knoxTokenMonitor != null) {
      knoxTokenMonitor.shutdown();
    }
  }

  //this is protected because it's used in the only-child AbfsTestIDBIntegration
  protected AbfsIDBClient getClient() throws IOException {
    if (idbClient == null) {
      idbClient = new AbfsIDBClient(configuration, owner);
    }
    return idbClient;
  }

  @Override
  protected void serviceStop() throws Exception {
    LOG.debug("Stopping IDB integration for ABFS filesystem {}", fsUri);
    stopKnoxTokenMonitor();
    super.serviceStop();
  }

  /**
   * Return the name of the owner to be used in tokens.
   * This may be that of the UGI owner, or it could be related to
   * the cloud storage login.
   *
   * @return a text name of the owner.
   */
  Text getOwnerText() {
    return new Text(getOwner().getUserName());
  }

  UserGroupInformation getOwner() {
    return owner;
  }

  /**
   * Make sure the service is started.
   *
   * @throws IllegalStateException if not.
   */
  private void checkStarted() {
    checkState(isInState(STATE.STARTED), "Service is in wrong state %s", getServiceState());
  }

  /**
   * Get the token deployed, or create a new one on demand.
   *
   * @param renewer token renewer
   * @return the token identifier
   * @throws IOException Failure
   */
  Token<AbfsIDBTokenIdentifier> getDelegationToken(final String renewer) throws IOException {

    getKnoxTokenLock.lock();
    try {
      LOG.debug("Delegation token requested");

      if (deployedToken != null) {
        LOG.debug("Returning existing delegation token");
        return deployedToken;
      }

      LOG.debug("Requesting new delegation token");

      ensureKnoxToken();
      ensureADToken();

      if (LOG.isDebugEnabled()) {
        LOG.debug("Knox token expires in {} seconds:" +
            "\n\tExpiry: {}",
            knoxToken.getExpiry() - Instant.now().getEpochSecond(),
            Instant.ofEpochSecond(knoxToken.getExpiry()).toString());
      }

      final String knoxDT = knoxToken == null ?  "" : knoxToken.getAccessToken();
      final long expiryTime = knoxToken == null ?  0L : knoxToken.getExpiry();
      final String endpointCertificate = knoxToken == null ?  "" : knoxToken.getEndpointPublicCert();

      final AbfsIDBTokenIdentifier id = new AbfsIDBTokenIdentifier(fsUri,
          getOwnerText(),
          (renewer == null) ? null : new Text(renewer),
              "origin",
              knoxDT,
              expiryTime,
              buildOAuthPayloadFromADToken(adToken),
              System.currentTimeMillis(),
              correlationId,
              idbClient.getCredentialsURL(),
              endpointCertificate);
      LOG.trace("New ABFS DT {}", id);
      final Token<AbfsIDBTokenIdentifier> token = new Token<>(id, secretManager);
      token.setService(service);

      return token;
    } finally {
      getKnoxTokenLock.unlock();
    }
  }

  private void ensureADToken() throws IOException {
    adToken = getADToken(true);
  }

  private void ensureKnoxToken() throws IOException {
    if (knoxToken == null) {
      if (idbClient.shouldExcludeUserFromGettingKnoxToken()) {
        LOG.info("'{}' is excluded from getting Knox Token from IDBroker", idbClient.getOwnerUserName());
      } else {
        LOG.info("There is no Knox Token available, fetching one from IDBroker...");
        getNewKnoxToken();
      }
    } else {
      LOG.info("Using existing Knox Token: " + Tokens.getTokenDisplayText(knoxToken.getAccessToken()));
    }
    Preconditions.checkNotNull(knoxToken, "Failed to retrieve a Knox Token from the IDBroker.");
  }

  /**
   * Find a token for the FS user and canonical filesystem URI.
   *
   * @return the token, or null if one cannot be found.
   * @throws IOException on a failure to unmarshall the token.
   */
  private Token<AbfsIDBTokenIdentifier> lookupTokenFromOwner() throws IOException {
    return lookupToken(owner.getCredentials(), service);
  }

  /**
   * Init the AD Credentials from either the deployed token/identifier
   * or the local configuration.
   *
   * @param deployedIdentifier
   */
  private AzureADToken buildADTokenCredentials(AbfsIDBTokenIdentifier deployedIdentifier) {
    AzureADToken adToken;

    if (deployedIdentifier != null) {
      LOG.debug("Using existing delegation token for Azure Credentials");
      adToken = buildADTokenFromOAuth(deployedIdentifier.getMarshalledCredentials());

      if (LOG.isTraceEnabled()) {
        if (adToken == null) {
          LOG.trace("AD Token: null");
        } else {
          LOG.trace("AD Token:\n\tToken:{}\n\tExpiry:{}", adToken.getAccessToken(), adToken.getExpiry().toInstant().toString());
        }
      }
    } else {
      LOG.debug("Delaying token creation until needed");
      adToken = null;
    }

    return adToken;
  }

  KnoxToken buildKnoxToken(AbfsIDBTokenIdentifier deployedIdentifier) {
    KnoxToken knoxToken = null;

    if (deployedIdentifier != null) {
      LOG.info("Using existing delegation token for Knox Token");
      knoxToken = new KnoxToken(deployedIdentifier.getOrigin(), deployedIdentifier.getAccessToken(), deployedIdentifier.getExpiryTime(), deployedIdentifier.getCertificate());

      if (LOG.isTraceEnabled()) {
        LOG.trace("Knox Token:\n\tToken:{}\n\tExpiry:{}",
                  knoxToken.getPrintableAccessToken(),
                  Instant.ofEpochSecond(knoxToken.getExpiry()).toString());
      }
    } else {
      LOG.debug("Delaying Knox token creation until needed");
    }

    return knoxToken;
  }

  /**
   * Gets an active directory token
   *
   * @return any AD token previously extracted
   */
  AzureADToken getADToken(boolean renewIfNeeded) throws IOException {
    getAzureADTokenLock.lock();
    try {
      LOG.trace("Get an AD Token");
      if ((adToken == null) || (renewIfNeeded && isExpired(adToken))) {
        if (LOG.isDebugEnabled()) {
          if (adToken == null) {
            LOG.debug("No existing AD Token found, getting a new one.");
          } else if (isExpired(adToken)) {
            LOG.debug("Existing AD Token found, but expired, getting a new one.");
          }
        }

        getNewAzureADToken();

        /* Retry in case the token is expired */
        int retry = 0;
        while (isExpired(adToken) && retry <= retryCount) {
          if (retry == retryCount) {
            /* Maximum retry count reached, throw exception */
            LOG.error(String.format(Locale.ROOT,
                "Reached maximum configured retries %s, token returned from IDBroker is expired, token expiry timestamp %s, current timestamp %s",
                retryCount, adToken.getExpiry(),
                System.currentTimeMillis() / 1000L));
            throw new IOException(String.format(Locale.ROOT,
                "Token returned from IDBroker is expired, token expiry timestamp %s, current timestamp %s",
                adToken.getExpiry(), System.currentTimeMillis() / 1000L));
          }
          try {
            TimeUnit.SECONDS.sleep(5);
          } catch (InterruptedException e) {
            throw new IOException(e);
          }
          LOG.info(
              "Received token was expired, attempting to get a new AD token, retry count: "
                  + retry);
          getNewAzureADToken();
          retry++;
        }

      } else {
        LOG.debug("Using existing AD Token");
      }

      return adToken;
    } finally {
      getAzureADTokenLock.unlock();
    }
  }

  /**
   * Get a suffix for the UserAgent suffix of HTTP requests, which
   * can be used to identify the principal making ABFS requests.
   *
   * @return the correlation ID created or retrieved from the DT.
   */
  String getUserAgentSuffix() {
    return "correlationId=" + correlationId;
  }

  /**
   * The canonical service name if that of the filesystem URI
   */
  String getCanonicalServiceName() {
    checkNotNull(fsUri, "Not bound to a filesystem URI");
    return fsUri.toString();
  }

  /**
   * Create an empty identifier for unmarshalling.
   *
   * @return an empty identifier.
   */
  private static AbfsIDBTokenIdentifier createEmptyIdentifier() {
    return new AbfsIDBTokenIdentifier();
  }

  /**
   * Look up a token from the credentials, verify it is of the correct
   * kind.
   *
   * @param credentials credentials to look up.
   * @param service     service name
   * @return the token or null if no suitable token was found
   * @throws IOException wrong token kind found
   */
  private Token<AbfsIDBTokenIdentifier> lookupToken(
      final Credentials credentials,
      final Text service)
      throws IOException {

    LOG.debug("Looking for token for service {} in credentials", service);
    Token<?> token = credentials.getToken(service);
    if (token != null) {
      Text tokenKind = token.getKind();
      LOG.debug("Found token of kind {}", tokenKind);
      if (IDB_TOKEN_KIND.equals(tokenKind)) {
        // the Oauth implementation catches and logs here; this one
        // throws the failure up.
        return (Token<AbfsIDBTokenIdentifier>) token;
      } else {

        // there's a token for this URI, but its not the right DT kind
        throw new IOException(
            "Token mismatch: expected token"
                + " for " + service
                + " of type " + IDB_TOKEN_KIND
                + " but got a token of type " + tokenKind);
      }
    }
    // A token for the service was not found
    LOG.debug("No token for {} found", service);
    return null;
  }

  /**
   * Get the password to use in secret managers.
   * This is a constant; its just recalculated every time to stop findbugs
   * highlighting security risks of shared mutable byte arrays.
   *
   * @return a password.
   */
  private static byte[] getSecretManagerPassword() {
    return "non-password".getBytes(Charset.forName("UTF-8"));
  }

  /**
   * The secret manager always uses the same secret; the
   * factory for new identifiers is that of the token manager.
   */
  protected static class TokenSecretManager
      extends SecretManager<AbfsIDBTokenIdentifier> {

    TokenSecretManager() {
    }

    @Override
    protected byte[] createPassword(AbfsIDBTokenIdentifier identifier) {
      return getSecretManagerPassword();
    }

    @Override
    public byte[] retrievePassword(AbfsIDBTokenIdentifier identifier) {
      return getSecretManagerPassword();
    }

    @Override
    public AbfsIDBTokenIdentifier createIdentifier() {
      return createEmptyIdentifier();
    }
  }

  /**
   * Create an Azure AD token from the auth payload.
   *
   * @param payload marshalled payload.
   * @return an Azure ADToken.
   */
  static AzureADToken buildADTokenFromOAuth(
      @Nonnull final OAuthPayload payload) {
    checkNotNull(payload, "no OAuth payload");
    final AzureADToken adToken = new AzureADToken();
    adToken.setAccessToken(payload.getToken());
    adToken.setExpiry(new Date(payload.getExpiration()));
    return adToken;
  }

  /**
   * From an AD token, build an OAuth payload.
   *
   * @param adToken source token.
   * @return a marshallable payload.
   */
  static OAuthPayload buildOAuthPayloadFromADToken(
      @Nonnull final AzureADToken adToken) {
    checkNotNull(adToken, "no adToken");
    return new OAuthPayload(
        adToken.getAccessToken(),
        adToken.getExpiry().getTime());
  }

  /**
   * Enable the custom credential and delegation token support.
   * This doesn't set any account-specific options.
   *
   * @param conf configuration to patch.
   */
  public static void enable(Configuration conf) {
    conf.setEnum(FS_AZURE_ACCOUNT_AUTH_TYPE_PROPERTY_NAME,
        AuthType.Custom);
    conf.set(FS_AZURE_ACCOUNT_TOKEN_PROVIDER_TYPE_PROPERTY_NAME,
        AbfsIDBCredentialProvider.class.getName());
    conf.setBoolean(FS_AZURE_ENABLE_DELEGATION_TOKEN, true);
    conf.set(FS_AZURE_DELEGATION_TOKEN_PROVIDER_TYPE,
        AbfsIDBDelegationTokenManager.NAME);
  }

  private boolean isExpired(AzureADToken azureADToken) {
    if (azureADToken == null) {
      return true;
    } else {
      Date expiry = adToken.getExpiry();
      return (expiry == null) || (expiry.toInstant().isBefore(Instant.now()));
    }
  }

  private void getNewAzureADToken() throws IOException {
    LOG.trace("Getting a new Azure AD Token");

    CloudAccessBrokerSession knoxCredentialsSession = getKnoxCredentialsSession();

    Preconditions.checkNotNull(knoxCredentialsSession, "Failed to obtain a session with the IDBroker.");

    adToken = idbClient.fetchCloudCredentials(knoxCredentialsSession);
    if (LOG.isTraceEnabled()) {
      if (adToken == null) {
        LOG.trace("AD Token: null");
      } else {
        LOG.trace("AD Token:\n\tToken:{}\n\tExpiry:{}", adToken.getAccessToken(), adToken.getExpiry().toInstant().toString());
      }
    }

    IOUtils.cleanupWithLogger(LOG, knoxCredentialsSession);
  }

  private void getNewKnoxToken() throws IOException {
    LOG.trace("Getting a new Knox Token");
    Pair<KnoxSession, String> sessionDetails = getNewKnoxLoginSession();
    KnoxSession knoxLoginSession = sessionDetails.getLeft();
    String origin = sessionDetails.getRight();

    Preconditions.checkNotNull(knoxLoginSession, "Failed to obtain a session with the IDBroker.");

    RequestDTResponseMessage message;
    try {
      message = idbClient.requestKnoxDelegationToken(knoxLoginSession, origin, fsUri);
    } finally {
      IOUtils.cleanupWithLogger(LOG, knoxLoginSession);
    }

    Preconditions.checkNotNull(message, "Failed to request a delegation token from the IDBroker.");

    knoxToken = KnoxToken.fromDTResponse(origin, message);
    if (LOG.isTraceEnabled()) {
      LOG.trace("Knox Token:\n\tToken:{}\n\tExpiry:{}",
                knoxToken.getPrintableAccessToken(),
                Instant.ofEpochSecond(knoxToken.getExpiry()).toString());
    }

    monitorKnoxToken();
  }

  private CloudAccessBrokerSession getKnoxCredentialsSession() throws IOException {
    ensureKnoxToken();
    return idbClient.createKnoxCABSession(knoxToken);
  }

  private Pair<KnoxSession, String> getNewKnoxLoginSession() throws IOException {
    checkStarted();

    LOG.debug("Attempting to create a Knox delegation token session using local credentials (kerberos, simple)");
    Pair<KnoxSession, String> sessionDetails = idbClient.createKnoxDTSession(configuration);
    if (sessionDetails.getLeft() != null) {
      LOG.debug("Created a Knox delegation token session using local credentials (kerberos, simple)");
    }

    if (sessionDetails.getLeft() == null) {
      /*
       * A session with Knox/IDBroker was not established.  Ideally this is due to an authentication
       * problem.  One of two scenarios may have occurred:
       *   1 - The Kerberos token is missing or expired and there is no Knox token
       *          Solution: the user must kinit
       *   2 - The Kerberos token is missing or expired and the exiting Knox token is expired
       *          Solution: the user must kinit, but this is probably not an option since execution
       *                    of this process has moved away from an interactive state (for example,
       *                    is it running as a MR job)
       */
      String message;

      if(knoxToken == null) {
        // A valid Kerberos token or Knox token is not available. To get a Knox token, the user needs
        // to authenticate with the IDBroker using Kerberos.
        message = MESSAGE_FAILURE_TO_AUTHENTICATE_TO_IDB_KERBEROS;
      }
      else {
        // A valid Kerberos token is not available and the existing Knox token is expired.  To get a
        // new Knox token, the user needs to authenticate with the IDBroker using Kerberos.
        message = MESSAGE_FAILURE_TO_AUTHENTICATE_TO_IDB_DT;
      }

      throw new IllegalStateException(message);
    }

    return sessionDetails;
  }

  private class GetKnoxTokenCommand implements KnoxTokenMonitor.GetKnoxTokenCommand {
    @Override
    public void execute(KnoxToken knoxToken) throws IOException {
      getKnoxTokenLock.lock();
      try {
        getNewKnoxToken();
      } finally {
        getKnoxTokenLock.unlock();
      }
    }
  }
}

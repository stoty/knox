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

import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_AUTH_TYPE_PROPERTY_NAME;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_TOKEN_PROVIDER_TYPE_PROPERTY_NAME;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_DELEGATION_TOKEN_PROVIDER_TYPE;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ENABLE_DELEGATION_TOKEN;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBConstants.IDB_TOKEN_KIND;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkState;

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
import org.apache.knox.gateway.cloud.idbroker.common.OAuthPayload;
import org.apache.knox.gateway.cloud.idbroker.common.Preconditions;
import org.apache.knox.gateway.cloud.idbroker.common.UTCClock;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

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
final class AbfsIDBIntegration extends AbstractService {

  private static final Logger LOG = LoggerFactory.getLogger(AbfsIDBIntegration.class);

  private URI fsUri;

  private Text service;

  private final Configuration configuration;

  /**
   * Cached principal.
   */
  private UserGroupInformation owner;

  /**
   * Client connection, created in service start.
   */
  private AbfsIDBClient idbClient;

  /**
   * The connection to the Knox DT-issuing endpoint.
   */
  private KnoxSession knoxLoginSession = null;
  private String knoxLoginSessionOrigin = null;

  /**
   * The connection to the Knox Cloud Credentials-issuing endpoint.
   */
  private KnoxSession knoxCredentialsSession = null;

  /**
   * Any deployed token.
   */
  private Token<AbfsIDBTokenIdentifier> deployedToken = null;

  /**
   * Decoded identifier of the deployed token.
   */
  private AbfsIDBTokenIdentifier deployedIdentifier = null;

  private KnoxToken knoxToken = null;

  private AzureADToken adToken = null;

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
                             @Nonnull final String origin)
      throws IOException {
    super("AbfsIDBIntegration");

    this.fsUri = checkNotNull(fsUri, "Filesystem URI");
    this.configuration = checkNotNull(configuration);
    // save the DT owner
    this.owner = UserGroupInformation.getLoginUser();

    this.service = new Text(fsUri.getScheme() + "://" + fsUri.getAuthority());

    if (LOG.isDebugEnabled() && !this.service.toString().equals(fsUri.toString())) {
      LOG.debug("Truncating service URI from {} to {} [{}]", fsUri, this.service, origin);
    }

    LOG.debug("Creating AbfsIDBIntegration:\n\tOrigin: {}\n\tService: {}\n\tOwner: {}", origin, this.service, this.owner.getUserName());
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
    super.serviceStart();
    LOG.debug("Starting IDB integration for ABFS filesystem {}", fsUri);

    idbClient = new AbfsIDBClient(configuration, owner);
    // retrieve the DT from the owner
    deployedToken = lookupTokenFromOwner();
    if (deployedToken != null) {
      AbfsIDBTokenIdentifier id = deployedToken.decodeIdentifier();
      deployedIdentifier = id;
      correlationId = id.getTrackingId();
      LOG.debug("Deployed for {} with token identifier {}", fsUri, id);
    }

    buildADTokenCredentials();
    buildKnoxToken();
  }

  @Override
  protected void serviceStop() throws Exception {
    IOUtils.cleanupWithLogger(LOG, knoxLoginSession, knoxCredentialsSession);
    super.serviceStop();
  }

  /**
   * Return the name of the owner to be used in tokens.
   * This may be that of the UGI owner, or it could be related to
   * the cloud storage login.
   *
   * @return a text name of the owner.
   */
  private Text getOwnerText() {
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
    checkState(isInState(STATE.STARTED),
        "Service is in wrong state %s", getServiceState());
  }

  /**
   * Get the token deployed, or create a new one on demand.
   *
   * @param renewer token renewer
   * @return the token identifier
   * @throws IOException Failure
   */
  Token<AbfsIDBTokenIdentifier> getDelegationToken(final String renewer)
      throws IOException {

    LOG.debug("Delegation token requested");

    if (deployedToken != null) {
      LOG.debug("Returning existing delegation token");
      return deployedToken;
    }

    LOG.debug("Requesting new delegation token");

    ensureKnoxToken();
    getADToken(true);

    AbfsIDBTokenIdentifier id = new AbfsIDBTokenIdentifier(fsUri,
        getOwnerText(),
        new Text(renewer),
        "origin",
        knoxToken.getAccessToken(),
        knoxToken.getExpiry(),
        buildOAuthPayloadFromADToken(adToken),
        System.currentTimeMillis(),
        correlationId, "", knoxToken.getEndpointPublicCert());
    LOG.trace("New ABFS DT {}", id);
    final Token<AbfsIDBTokenIdentifier> token = new Token<>(id, secretManager);
    token.setService(service);

    return token;
  }

  private void ensureKnoxToken() throws IOException {
    if ((knoxToken == null) || knoxToken.isExpired()) {
      getNewKnoxToken();
    }

    Preconditions.checkNotNull(knoxToken, "Failed to retrieve a delegation token from the IDBroker.");
  }

  /**
   * Find a token for the FS user and canonical filesystem URI.
   *
   * @return the token, or null if one cannot be found.
   * @throws IOException on a failure to unmarshall the token.
   */
  private Token<AbfsIDBTokenIdentifier> lookupTokenFromOwner()
      throws IOException {
    return lookupToken(owner.getCredentials(), service);
  }

  /**
   * Init the AD Credentials from either the deployed token/identifier
   * or the local configuration.
   */
  private void buildADTokenCredentials() {
    if (deployedIdentifier != null) {
      LOG.debug("Using existing delegation token for Azure Credentials");
      adToken = buildADTokenFromOAuth(deployedIdentifier.getMarshalledCredentials());

      if (LOG.isTraceEnabled()) {
        if (adToken == null) {
          LOG.trace("AD Token: null");
        } else {
          LOG.trace("AD Token:\n\tToken:{}\n\tExpiry:{}", adToken.getAccessToken(), UTCClock.secondsToString(adToken.getExpiry().getTime()));
        }
      }
    } else {
      LOG.debug("Delaying token creation until needed");
      adToken = null;
    }
  }

  private void buildKnoxToken() {
    if (deployedIdentifier != null) {
      LOG.debug("Using existing delegation token for Knox Token");
      knoxToken = new KnoxToken(deployedIdentifier.getAccessToken(), deployedIdentifier.getExpiryTime(), deployedIdentifier.getCertificate());

      if (LOG.isTraceEnabled()) {
        LOG.trace("Knox Token:\n\tToken:{}\n\tExpiry:{}", knoxToken.getAccessToken(), UTCClock.secondsToString(knoxToken.getExpiry()));
      }
    } else {
      LOG.debug("Delaying Knox token creation until needed");
      knoxToken = null;
    }
  }

  /**
   * Gets an active directory token
   *
   * @return any AD token previously extracted
   */
  AzureADToken getADToken(boolean renewIfNeeded) throws IOException {
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
    } else {
      LOG.debug("Using existing AD Token");
    }

    return adToken;
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

  private synchronized void getNewAzureADToken() throws IOException {
    LOG.trace("Getting a new Azure AD Token");
    if (knoxCredentialsSession == null) {
      getKnoxCredentialsSession();
    }

    Preconditions.checkNotNull(knoxCredentialsSession, "Failed to obtain a session with the IDBroker.");

    adToken = idbClient.fetchCloudCredentials(knoxCredentialsSession);
    if (LOG.isTraceEnabled()) {
      if (adToken == null) {
        LOG.trace("AD Token: null");
      } else {
        LOG.trace("AD Token:\n\tToken:{}\n\tExpiry:{}", adToken.getAccessToken(), UTCClock.secondsToString(adToken.getExpiry().getTime()));
      }
    }
  }

  private synchronized void getNewKnoxToken() throws IOException {
    LOG.trace("Getting a new Knox Token");
    if (knoxLoginSession == null) {
      getNewKnoxLoginSession();
    }

    Preconditions.checkNotNull(knoxLoginSession, "Failed to obtain a session with the IDBroker.");

    RequestDTResponseMessage message = idbClient.requestKnoxDelegationToken(knoxLoginSession, knoxLoginSessionOrigin, fsUri);

    Preconditions.checkNotNull(message, "Failed to request a delegation token from the IDBroker.");

    knoxToken = new KnoxToken(message.access_token, message.expiryTimeSeconds(), message.endpoint_public_cert);
    if (LOG.isTraceEnabled()) {
      LOG.trace("Knox Token:\n\tToken:{}\n\tExpiry:{}", knoxToken.getAccessToken(), UTCClock.secondsToString(knoxToken.getExpiry()));
    }
  }

  private synchronized void getKnoxCredentialsSession() throws IOException {
    if ((knoxToken == null) || knoxToken.isExpired()) {
      getNewKnoxToken();
    }

    Preconditions.checkNotNull(knoxToken, "Failed to retrieve a delegation token from the IDBroker.");

    knoxCredentialsSession = idbClient.cloudSessionFromDelegationToken(
        knoxToken.getAccessToken(),
        idbClient.getCredentialsURL(),
        knoxToken.getEndpointPublicCert());
  }

  private synchronized void getNewKnoxLoginSession() throws IOException {
    LOG.trace("Get a new Knox session....");
    checkStarted();

    if (deployedIdentifier != null) {
      LOG.debug("Get a new Knox session from Delegation token");
      knoxLoginSession = idbClient.cloudSessionFromDelegationToken(deployedIdentifier.getAccessToken(), deployedIdentifier.getEndpoint(), deployedIdentifier.getCertificate());
      knoxLoginSessionOrigin = "IDBroker access token from Delegation Token " + deployedIdentifier.getOrigin();
    } else {
      LOG.debug("Create a new Knox session");
      Pair<KnoxSession, String> result = idbClient.login(configuration);
      knoxLoginSession = result.getLeft();
      knoxLoginSessionOrigin = result.getRight();
    }
    LOG.debug("Using {}", knoxLoginSessionOrigin);
  }

  private class KnoxToken {
    private final String accessToken;
    private final Long expiry;
    private final String endpointPublicCert;

    private KnoxToken(String accessToken, Long expiry, String endpointPublicCert) {
      this.accessToken = accessToken;
      this.expiry = expiry;
      this.endpointPublicCert = endpointPublicCert;
    }

    public String getAccessToken() {
      return accessToken;
    }

    public Long getExpiry() {
      return expiry;
    }

    public String getEndpointPublicCert() {
      return endpointPublicCert;
    }

    public boolean isExpired() {
      return (expiry == null) || expiry < System.currentTimeMillis();
    }
  }
}

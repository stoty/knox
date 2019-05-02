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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import com.google.common.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.AbfsConfiguration;
import org.apache.hadoop.fs.azurebfs.contracts.exceptions.FileSystemOperationUnhandledException;
import org.apache.hadoop.fs.azurebfs.oauth2.AccessTokenProvider;
import org.apache.hadoop.fs.azurebfs.oauth2.AzureADToken;
import org.apache.hadoop.fs.azurebfs.oauth2.ClientCredsTokenProvider;
import org.apache.hadoop.fs.azurebfs.services.AuthType;
import org.apache.hadoop.fs.s3a.commit.DurationInfo;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.SecretManager;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.service.AbstractService;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.OAuthPayload;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;

import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkState;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_AUTH_TYPE_PROPERTY_NAME;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_OAUTH_CLIENT_ENDPOINT;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_OAUTH_CLIENT_ID;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_OAUTH_CLIENT_SECRET;
import static org.apache.knox.gateway.cloud.idbroker.IDBClient.createFullIDBClient;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_TOKEN_PROVIDER_TYPE_PROPERTY_NAME;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_DELEGATION_TOKEN_PROVIDER_TYPE;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ENABLE_DELEGATION_TOKEN;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDB_ABFS_TOKEN_KIND;

/**
 * The class which does the real integration between ABFS and IDB.
 * Independent instances are shared in both 
 * {@link AbfsIDBDelegationTokenManager} and {@link AbfsIDBCredentialProvider},
 * which makes the code a bit messy.
 * 
 * There are essentially two instantiation paths
 * 
 * 1. credential provider: looks for DT credentials for the current FS,
 * and if found, uses them. If not falls back to IDBroker.
 * TODO: Use IDBroker.
 * 
 * 2. DT manager. Recycles existing DT credentials if asked, else builds
 * some with the help of IDBroker.
 * TODO: Use IDBroker.
 * 
 * Both are incomplete at present as we don't have IDBroker issuing any
 * Azure tokens. Instead we fallback to local OAuth secrets.
 * 
 */
final class AbfsIDBIntegration extends AbstractService {

  private static final Logger LOG =
      LoggerFactory.getLogger(AbfsIDBIntegration.class);
  
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
  private IDBClient idbClient;
  
  /**
   * Knox session is only created on demand.
   * It is closed in service close.
   */
  private Optional<KnoxSession> knoxSession = Optional.empty();

  private String knoxSessionOrigin = "";

  /**
   * This is a connection to the knox DT issuing endpoint.
   * it is non-empty if this binding was instantiated without
   * a delegation token, that is: new DTs can be requested.
   */
  private Optional<KnoxSession> loginSession = Optional.empty();

  private String endpoint = "";

  private String endpointCertificate = "";

  /**
   * Any deployed token.
   */
  private Optional<Token<AbfsIDBTokenIdentifier>> deployedToken =
       Optional.empty();

  /**
   * Decoded identifier of the deployed token.
   */
  private Optional<AbfsIDBTokenIdentifier> deployedIdentifier =
      Optional.empty();

  private AccessTokenProvider adTokenProvider;

  private AbfsConfiguration abfsConf;

  /**
   * AD token. This is never null once bound to either a DT or
   * locally started.
   */
  private AzureADToken adToken;
  
  private final String accountName;

  /**
   * A correlation ID.
   * If an existing DT is found, its correlation ID will be extracted and
   * used/propagated.
   */
  private String correlationId = UUID.randomUUID().toString();

  /**
   * Secret manager to use.
   */
  private static final SecretManager<AbfsIDBTokenIdentifier>
      secretManager = new TokenSecretManager();

  /**
   * Instantiate.
   * As well as binding the fsUri and configuration fields, the owner
   * is set to the current user.
   * @param fsUri filesystem URI
   * @param configuration filesystem configuration 
   * @param accountName Azure account name
   * @throws IOException failure
   */
  private AbfsIDBIntegration(
      @Nonnull final URI fsUri,
      @Nonnull final Configuration configuration,
      @Nullable final String accountName)
      throws IOException {
    super("AbfsIDBIntegration");
    this.fsUri = checkNotNull(fsUri, "Filesystem URI");
    this.configuration = checkNotNull(configuration);
    this.accountName = accountName;
    // save the DT owner
    this.owner = UserGroupInformation.getCurrentUser();
    this.service = new Text(fsUri.toString());
  }

  /**
   * Create as part of the binding process for an Azure Delegation Token manager.
   * @param fsUri filesystem URI.
   * @param conf configuration.
   * @return a started instance.
   * @throws IOException failure
   */
  static AbfsIDBIntegration fromDelegationTokenManager(
      final URI fsUri,
      final Configuration conf) throws IOException {
    AbfsIDBIntegration integration = new AbfsIDBIntegration(fsUri, conf, "");
    integration.init(conf);
    integration.start();
    return integration;
  }

  /**
   * Create as part of the binding process of an Azure credential provider.
   * @param fsUri filesystem URI.
   * @param conf configuration.
   * @param accountName Azure account name.
   * @return a started instance.
   * @throws IOException failure
   */
  static AbfsIDBIntegration fromAbfsCredentialProvider(
      final URI fsUri,
      final Configuration conf,
      final String accountName) throws IOException {
    AbfsIDBIntegration integration = new AbfsIDBIntegration(fsUri, conf,
        accountName);
    integration.init(conf);
    integration.start();
    return integration;
  }

  /**
   * Start the service.
   * This includes looking up for any DT of the current user.
   * @throws Exception failure.
   */
  @Override
  protected void serviceStart() throws Exception {
    super.serviceStart();
    LOG.info("Starting IDB integration for ABFS filesystem {}", fsUri);

    idbClient = createFullIDBClient(getConfig(), owner);
    // retrieve the DT from the owner
    Token<AbfsIDBTokenIdentifier> token = lookupTokenFromOwner();
    deployedToken = Optional.ofNullable(token);
    if (token != null) {
      AbfsIDBTokenIdentifier id = token.decodeIdentifier();
      deployedIdentifier = Optional.of(id);
      correlationId = id.getTrackingId();
      endpoint = id.getEndpoint();
      endpointCertificate = id.getCertificate();
      LOG.debug("Deployed for {} with token identifier {}", fsUri, id);
      LOG.info("Authenticating through supplied delegation token");
    }
    // now set up the AD token 
    buildADTokenCredentials();
  }

  @Override
  protected void serviceStop() throws Exception {
    IOUtils.cleanupWithLogger(LOG, knoxSession.orElse(null));
    super.serviceStop();
  }

  /**
   * Return the name of the owner to be used in tokens.
   * This may be that of the UGI owner, or it could be related to
   * the AWS login.
   * @return a text name of the owner.
   */
   Text getOwnerText() {
    return new Text(getOwner().getUserName());
  }

   UserGroupInformation getOwner() {
    return owner;
  }

  /**
   * Does this instance have a deployed token to use for authentication.
   * @return true if a token was found for this FS URI.
   */
   boolean hasDeployedToken() {
    return deployedToken.isPresent();
  }

   Optional<Token<AbfsIDBTokenIdentifier>> getDeployedToken() {
    return deployedToken;
  }

   Optional<AbfsIDBTokenIdentifier> getDeployedIdentifier() {
    return deployedIdentifier;
  }

  /**
   * Get or create the knox session.
   * If a DT was supplied, the token identifier in it is used.
   * Otherwise, a kerberos session is used to authenticate the caller.
   * @return a knox session.
   * @throws IOException failure.
   */
  private synchronized Pair<KnoxSession, String> knoxSession() throws IOException {
    checkStarted();
    String origin;
    if (!knoxSession.isPresent()) {
      // always log in via K-auth
      LOG.debug("Creating Knox Session");
      KnoxSession session;
      if (deployedIdentifier.isPresent()) {
        AbfsIDBTokenIdentifier identifier
            = deployedIdentifier.get();
        origin = "IDBroker access token from Delegation Token " +
          identifier.getOrigin();
        LOG.debug("Using {}", origin);
        session = idbClient.cloudSessionFromDelegationToken(
            identifier.getAccessToken(), endpoint, endpointCertificate);
      } else {
        origin = "Local Kerberos login";
        session = idbClient.knoxSessionFromKerberos();
      }
      knoxSession = Optional.of(session);
      knoxSessionOrigin = origin;
      return Pair.of(session, origin);
    }
    return Pair.of(knoxSession.get(), knoxSessionOrigin);
  }

  /**
   * Make sure the service is started.
   * @throws IllegalStateException if not.
   */
  private void checkStarted() {
    checkState(isInState(STATE.STARTED),
        "Service is in wrong state %s", getServiceState());
  }

  /**
   * Get the token deployed, or create a new one on demand.
   * @param renewer token renewer
   * @return the token identifier
   * @throws IOException Failure
   */
  Token<AbfsIDBTokenIdentifier> getDelegationToken(final String renewer)
      throws IOException {

    LOG.debug("Delegation token requested");
    if (deployedToken.isPresent()) {
      LOG.debug("Returning existing delegation token");
      return deployedToken.get();
    }
    LOG.debug("Requesting new delegation token");
    Pair<KnoxSession, String> pair = knoxSession();
    RequestDTResponseMessage message
        = idbClient.requestKnoxDelegationToken(
            pair.getLeft(), pair.getRight(), fsUri);
    AbfsIDBTokenIdentifier id = new AbfsIDBTokenIdentifier(fsUri,
        getOwnerText(),
        new Text(renewer),
        "origin",
        message.access_token,
        message.expiryTimeSeconds(),
        buildOAuthPayloadFromADToken(adToken),
        System.currentTimeMillis(),
        correlationId, "", message.endpoint_public_cert);
    LOG.debug("New ABFS DT {}", id);
    final Token<AbfsIDBTokenIdentifier> token = new Token<>(id, secretManager);
    token.setService(service);

    return token;
  }

  /**
   * Find a token for the FS user and canonical filesystem URI.
   * @return the token, or null if one cannot be found.
   * @throws IOException on a failure to unmarshall the token.
   */
  Token<AbfsIDBTokenIdentifier> lookupTokenFromOwner()
      throws IOException {
    return lookupToken(owner.getCredentials(),
        service,
        IDB_ABFS_TOKEN_KIND);
  }

  /**
   * Init the AD Credentials from either the deployed token/identifier
   * or the local configuration.
   * @throws IOException failure
   */
  private void buildADTokenCredentials() throws IOException {
    if (deployedIdentifier.isPresent()) {
      LOG.info("Using existing delegation token for Azure Credentials");
      adToken = buildADTokenFromOAuth(
          deployedIdentifier.get().getMarshalledCredentials());
    } else {
      LOG.debug("Using local configuration to Azure Credentials");
      abfsConf = createAbfsConfiguration(configuration, accountName);
      adTokenProvider = createADTokenProvider(abfsConf);
      adToken = adTokenProvider.getToken();
    }
  }

  /**
   * Get the AD token string.
   * @return a token string for auth
   * @throws NoSuchElementException if there is no AD Token
   */
  String getADTokenString() {
    return adToken.getAccessToken();
  }

  /**
   * Gets an active directory token
   * @return any AD token previously extracted
   */
  AzureADToken getADToken() {
    return adToken;
  }

  /**
   * Get the expiry of the token
   * @return the expiry, or null if there is no AD Token.
   */ 
  Date getADTokenExpiryTime() {
    return adToken.getExpiry();
  }

  /**
   * Get a suffix for the UserAgent suffix of HTTP requests, which
   * can be used to identify the principal making ABFS requests.
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
   * Create the AD token provider to help authenticate the caller in the case
   * there is no DT to auth.
   * This is just an interim piece of code.
   * @param abfsConf ABFS configuration.
   * @return the token provider.
   * @throws IOException failure
   */
  AccessTokenProvider createADTokenProvider(final AbfsConfiguration abfsConf)
      throws IOException {
    String authEndpoint = getPasswordString(abfsConf,
        FS_AZURE_ACCOUNT_OAUTH_CLIENT_ENDPOINT);
    String clientId = getPasswordString(abfsConf,
        FS_AZURE_ACCOUNT_OAUTH_CLIENT_ID);
    String clientSecret = getPasswordString(abfsConf,
        FS_AZURE_ACCOUNT_OAUTH_CLIENT_SECRET);
    return new ClientCredsTokenProvider(
        authEndpoint, clientId,
        clientSecret);
  }

  /**
   * Get the password string for a key, checks and fails on a null value.
   * @param abfsConf abfs configuration
   * @param key key to look up
   * @return value of the key
   * @throws IOException on failure to retrieve a password.
   * @throws IllegalStateException if there was no entry for that key.
   */
  private String getPasswordString(final AbfsConfiguration abfsConf,
      final String key) throws IOException {
    String s = abfsConf.getPasswordString(key);
    checkState(s != null,
        "No configuration value for key %s", key);
    return s;
  }

  /**
   * Create an ABFS Configuration object, raises IOEs on failures.
   * @param configuration hadoop configuration.
   * @param accountName name of the account.
   * @return an ABFS configuration instance.
   * @throws IOException failure.
   */
  static AbfsConfiguration createAbfsConfiguration(
      final Configuration configuration,
      final String accountName)
      throws IOException {
    try {
      return new AbfsConfiguration(configuration, accountName);
    } catch (IllegalAccessException e) {
      throw new FileSystemOperationUnhandledException(e);
    }
  }
  
  /**
   * Create an empty identifier for unmarshalling.
   * @return an empty identifier.
   */
  static AbfsIDBTokenIdentifier createEmptyIdentifier() {
    return new AbfsIDBTokenIdentifier();
  }

  /**
   * Look up a token from the credentials, verify it is of the correct
   * kind.
   * @param credentials credentials to look up.
   * @param service service name
   * @param kind token kind to look for
   * @return the token or null if no suitable token was found
   * @throws IOException wrong token kind found
   */
  @VisibleForTesting
  public static Token<AbfsIDBTokenIdentifier> lookupToken(
      final Credentials credentials,
      final Text service,
      final Text kind)
      throws IOException {

    LOG.debug("Looking for token for service {} in credentials", service);
    Token<?> token = credentials.getToken(service);
    if (token != null) {
      Text tokenKind = token.getKind();
      LOG.debug("Found token of kind {}", tokenKind);
      if (kind.equals(tokenKind)) {
        // the Oauth implementation catches and logs here; this one
        // throws the failure up.
        return (Token<AbfsIDBTokenIdentifier>) token;
      } else {

        // there's a token for this URI, but its not the right DT kind
        throw new IOException(
            "Token mismatch: expected token"
                + " for " + service
                + " of type " + kind
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
   * @return a password.
   */
  private static byte[] getSecretManagerPasssword() {
    return "non-password".getBytes(Charset.forName("UTF-8"));
  }
  
  /**
   * The secret manager always uses the same secret; the
   * factory for new identifiers is that of the token manager.
   */
  protected static class TokenSecretManager
      extends SecretManager<AbfsIDBTokenIdentifier> {

    public TokenSecretManager() {
    }

    @Override
    protected byte[] createPassword(AbfsIDBTokenIdentifier identifier) {
      return getSecretManagerPasssword();
    }

    @Override
    public byte[] retrievePassword(AbfsIDBTokenIdentifier identifier)
        throws InvalidToken {
      return getSecretManagerPasssword();
    }

    @Override
    public AbfsIDBTokenIdentifier createIdentifier() {
      try (DurationInfo ignored = new DurationInfo(LOG,
          "Creating Delegation Token Identifier")) {
        return createEmptyIdentifier();
      }
    }
  }

  /**
   * Create an Azure AD token from the auth payload.
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
   * @param conf configuration to patch.
   */
  public static void enable(Configuration conf) {
    conf.setEnum(FS_AZURE_ACCOUNT_AUTH_TYPE_PROPERTY_NAME,
        AuthType.Custom);
    conf.set(FS_AZURE_ACCOUNT_TOKEN_PROVIDER_TYPE_PROPERTY_NAME,
        AbfsIDBCredentialProvider.NAME);
    conf.setBoolean(FS_AZURE_ENABLE_DELEGATION_TOKEN, true);
    conf.set(FS_AZURE_DELEGATION_TOKEN_PROVIDER_TYPE,
        AbfsIDBDelegationTokenManager.NAME);
  }

}

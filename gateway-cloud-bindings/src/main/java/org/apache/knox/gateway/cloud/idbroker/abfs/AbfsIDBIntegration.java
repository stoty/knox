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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Optional;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.AbfsConfiguration;
import org.apache.hadoop.fs.azurebfs.contracts.exceptions.FileSystemOperationUnhandledException;
import org.apache.hadoop.fs.azurebfs.oauth2.AccessTokenProvider;
import org.apache.hadoop.fs.azurebfs.oauth2.AzureADToken;
import org.apache.hadoop.fs.azurebfs.oauth2.ClientCredsTokenProvider;
import org.apache.hadoop.fs.s3a.commit.DurationInfo;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.SecretManager;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.service.AbstractService;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.common.OAuthPayload;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;

import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_OAUTH_CLIENT_ENDPOINT;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_OAUTH_CLIENT_ID;
import static org.apache.hadoop.fs.azurebfs.constants.ConfigurationKeys.FS_AZURE_ACCOUNT_OAUTH_CLIENT_SECRET;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDB_ABFS_TOKEN_KIND;

/**
 * The class which does the real integration between ABFS and IDB;
 * independent instances are shared in both 
 * {@link AbfsIDBDelegationTokenIssuer} and {@link AbfsIDBCredentialProvider}
 */
final class AbfsIDBIntegration extends AbstractService {

  private static final Logger LOG =
      LoggerFactory.getLogger(AbfsIDBIntegration.class);

  /**
   * This is a hard-coded FS URI until we can get the real FS URI from
   * ABFS initialization.
   */
  static final URI FS_URI;

  static {
    try {
      FS_URI = new URI(IDBConstants.IDB_ABFS_CANONICAL_NAME);
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }
  
  private final URI fsUri;
  
  private final Text service;
  
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

  /**
   * This is a connection to the knox DT issuing endpoint.
   * it is non-empty if this binding was instantiated without
   * a delegation token, that is: new DTs can be requested.
   * Will be set in {@link #deployUnbonded()}.
   */
  private Optional<KnoxSession> loginSession = Optional.empty();

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

  private Optional<AzureADToken> adToken = Optional.empty();
  
  private final String accountName;

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
      final URI fsUri,
      final Configuration configuration,
      final String accountName)
      throws IOException {
    super("AbfsIDBIntegration");
    this.fsUri = fsUri;
    this.configuration = configuration;
    this.accountName = accountName;
    // save the DT owner
    this.owner = UserGroupInformation.getCurrentUser();
    this.service = new Text(fsUri.toString());
  }

  static AbfsIDBIntegration fomDTIssuer(final URI fsUri,
      final Configuration conf) throws IOException {
    AbfsIDBIntegration integration = new AbfsIDBIntegration(fsUri, conf, "");
    integration.init(conf);
    integration.start();
    return integration;
  }

  static AbfsIDBIntegration fromAbfsCredentialProvider(
      final URI fsUri,
      final Configuration conf,
      final String accountName) throws IOException {
    AbfsIDBIntegration integration = new AbfsIDBIntegration(fsUri, conf,
        accountName);
    integration.init(conf);
    integration.start();
    integration.initADTokenCredentials();
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

    idbClient = new IDBClient(getConfig());
    Token<AbfsIDBTokenIdentifier> t = lookupTokenFromOwner();
    deployedToken = Optional.ofNullable(t);
    if (t != null) {
      AbfsIDBTokenIdentifier id = t.decodeIdentifier();
      deployedIdentifier = Optional.of(id);
      LOG.debug("Deployed for {} with token identifier {}", fsUri, id);
    }
  }

  @Override
  protected void serviceStop() throws Exception {
    super.serviceStop();
    IOUtils.cleanupWithLogger(LOG, knoxSession.orElse(null));
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

   boolean hasToken() {
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
  private synchronized KnoxSession knoxSession() throws IOException {
    checkStarted();
    if (!knoxSession.isPresent()) {
      // always log in via K-auth
      LOG.debug("Creating Knox Session");
      KnoxSession session;
      if (deployedIdentifier.isPresent()) {
        LOG.debug("Using token of supplied Delegation Token");
        session = idbClient.cloudSessionFromDT(
            deployedIdentifier.get().getAccessToken());
      } else {
        session = idbClient.knoxDtSession();
      }
      knoxSession = Optional.of(session);
      return session;
    }
    return knoxSession.get();
  }

  /**
   * Make sure the service is started.
   * @throws IllegalStateException if not.
   */
  private void checkStarted() {
    Preconditions.checkState(isInState(STATE.STARTED),
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

    LOG.info("Delegation token requested");
    if (deployedToken.isPresent()) {
      LOG.info("Returning existing delegation token");
      return deployedToken.get();
    }
    LOG.info("Requesting new delegation token");
    RequestDTResponseMessage message
        = idbClient.requestKnoxDelegationToken(knoxSession());
    AbfsIDBTokenIdentifier id = new AbfsIDBTokenIdentifier(fsUri,
        getOwnerText(),
        new Text(renewer),
        "origin",
        message.access_token,
        message.expiryTimeSeconds(),
        new OAuthPayload(),
        System.currentTimeMillis(),
        "correlationId");
    LOG.debug("New ABFS DT {}", id);
    Token<AbfsIDBTokenIdentifier> t = new Token<>(id, secretManager);
    t.setService(service);
    
    return t;
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

  
  void initADTokenCredentials() throws IOException {
    abfsConf = createAbfsConfiguration(configuration,
        accountName);
    adTokenProvider = createADTokenProvider(abfsConf);
    adToken = Optional.of(adTokenProvider.getToken());
  }

  /**
   * Get the AD token string.
   * @return a token string for auth
   * @throws NoSuchElementException if there is no AD Token
   */
  String getADTokenString() throws IOException {
    return adToken.map(AzureADToken::toString).get();
  }

  /**
   * Gets an active directory token
   * @return any AD token previously extracted
   */
  AzureADToken getADToken() throws IOException {
    return adToken.get();
  }

  /**
   * Get the expiry of the token
   * @return the expiry, or null if there is no AD Token.
   */ 
  Date getADTokenExpiryTime() {
    return adToken.map(AzureADToken::getExpiry).orElse(null);
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
    String authEndpoint = abfsConf.getPasswordString(
        FS_AZURE_ACCOUNT_OAUTH_CLIENT_ENDPOINT);
    String clientId = abfsConf.getPasswordString(
        FS_AZURE_ACCOUNT_OAUTH_CLIENT_ID);
    String clientSecret = abfsConf.getPasswordString(
        FS_AZURE_ACCOUNT_OAUTH_CLIENT_SECRET);
    return new ClientCredsTokenProvider(
        authEndpoint, clientId,
        clientSecret);
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


}

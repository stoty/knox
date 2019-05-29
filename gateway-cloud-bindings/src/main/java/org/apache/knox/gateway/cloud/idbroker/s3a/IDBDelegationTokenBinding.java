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

package org.apache.knox.gateway.cloud.idbroker.s3a;

import static org.apache.knox.gateway.cloud.idbroker.s3a.IDBS3AConstants.IDB_TOKEN_KIND;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBClient.createFullIDBClient;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBClient.createLightIDBClient;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_INIT_CAB_CREDENTIALS;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_USERNAME;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.PathAccessDeniedException;
import org.apache.hadoop.fs.s3a.AWSCredentialProviderList;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.S3AUtils;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentialBinding;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.NoAuthWithAWSException;
import org.apache.hadoop.fs.s3a.auth.RoleModel;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractDelegationTokenBinding;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.fs.s3a.auth.delegation.DelegationTokenIOException;
import org.apache.hadoop.fs.s3a.auth.delegation.EncryptionSecrets;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.common.UTCClock;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.PrivilegedExceptionAction;
import java.util.Objects;
import java.util.Optional;

/**
 * Binding of IDB DTs to S3A.
 *
 * <pre>
 *   An  {@link IDBS3ATokenIdentifier} token consists of: 
 *      -IDB token: String
 *      -marshalledCredentials: MarshalledCredentials 
 *      -rolePolicy
 *   The marshalled credentials may or may not contain session secrets;
 *   they are also used to marshall encryption settings.
 * </pre>
 *
 * Workflow
 * <pre>
 *   Created on a client without a token
 *     -get knox token from IDB.
 *     -then get AWS credentials from that.
 *
 *   When asked for a DT
 *     -get (new) knox token from IDB.
 *     -and a set of AWS Credentials, which get marshalled.
 *
 *   Created with a DT
 *     -load knox DT.
 *     -get AWS credentials from the DT. 
 *     -if they haven't expired: use.
 *     -if they have expired: request new ones.
 *
 *   Also need to handle: expiry of AWS credentials.
 * </pre>
 */
public class IDBDelegationTokenBinding extends AbstractDelegationTokenBinding {

  public static final String E_NO_ACQUIRE_TOKEN_FROM_TOKEN
      = "Cannot acquire Knox token unless logged in; using %s";

  public static final String E_NO_ACQUIRE_TOKEN_WHEN_HAS_EXPIRED
      = "Knox token has expired; the current token is %s";

  public static final String E_NO_KNOX_DELEGATION_TOKEN
      = "No Knox delegation token";

  public static final String E_NO_SESSION_TO_KNOX_AWS
      = "No session to knox AWS credential endpoint";

  protected static final Logger LOG =
      LoggerFactory.getLogger(IDBDelegationTokenBinding.class);

  /**
   * Wire name of this binding: {@value}.
   */
  private static final String NAME = "IDBDelegationToken";

  /**
   * Name as used in generated exceptions {@value}.
   */
  public static final String COMPONENT_NAME = NAME;

  /**
   * There's only one credential provider; this ensures that
   * its synchronized calls really do get locks.
   */
  private AWSCredentialProviderList credentialProviders;

  /**
   * Session credentials: initially empty.
   */
  private Optional<MarshalledCredentials> marshalledCredentials
      = Optional.empty();

  /**
   * Client connection, created in start.
   */
  private S3AIDBClient idbClient;

  private UTCClock clock = new UTCClock();

  /**
   * This is a connection to the knox DT issuing endpoint.
   * it is non-empty if this binding was instantiated without
   * a delegation token, that is: new DTs can be requested.
   * Will be set in {@link #deployUnbonded()}.
   */
  private Optional<KnoxSession> loginSession = Optional.empty();

  private String loginSessionOrigin = "";

  /**
   * The token identifier bound to in
   * {@link #bindToTokenIdentifier(AbstractS3ATokenIdentifier)}.
   */
  private Optional<IDBS3ATokenIdentifier> boundTokenIdentifier
      = Optional.empty();

  /**
   * This is the knox token.
   */
  private Optional<String> accessToken = Optional.empty();

  /**
   * The session to the AWS credential issuing endpoint.
   */
  private Optional<CloudAccessBrokerSession> awsCredentialSession = Optional.empty();

  /**
   * Expiry time for the DT.
   */
  private long accessTokenExpiresSeconds;

  /**
   * Login information; if empty: no login.
   */
  private Optional<Pair<String, String>> loginSecrets = Optional.empty();

  /**
   * Should AWS Credentials be collected when issuing a DT?
   */
  private boolean collectAwsCredentials = true;

  /**
   * Certificate of the gateway
   */
  private String gatewayCertificate = "";
  
  /**
   * Reflection-based constructor.
   */
  public IDBDelegationTokenBinding() {
    this(NAME, IDB_TOKEN_KIND);
  }

  /**
   * Constructor.
   * @param name binding name
   * @param kind token kind.
   */
  public IDBDelegationTokenBinding(final String name,
      final Text kind) {
    super(name, kind);
  }

  /**
   * Fetch the AWS credentials as a marshalled set of credentials.
   * @param credentialSession session to use.
   * @return AWS credentials.
   * @throws IOException failure.
   */
  @VisibleForTesting
  protected MarshalledCredentials fetchMarshalledAWSCredentials(
      S3AIDBClient client,
      CloudAccessBrokerSession credentialSession)
      throws IOException {
    return client.fetchCloudCredentials(credentialSession);
  }

  /**
   * Bond to the response of a knox login + DT request.
   * This doesn't kick off the first retrieval of secrets.
   * @param response response from the DT request.
   * @throws IOException failure to get an AWS credential session
   */
  public void bondToRequestedToken(final RequestDTResponseMessage response)
      throws IOException {
    final String token = extractTokenFromResponse(response);
    // print a small bit of the secret
    LOG.debug("Bonded to Knox token {}", token.substring(0, 10));
    accessToken = Optional.of(token);
    accessTokenExpiresSeconds = response.expiryTimeSeconds();
    gatewayCertificate = extractGatewayCertificate(response);
    if (gatewayCertificate.isEmpty()) {
      LOG.warn("No certificate provided by gateway: renewals will not work");
    }
    awsCredentialSession = Optional.of(
        idbClient.cloudSessionFromDelegationToken(token,
                                                  gatewayCertificate));
  }

  /**
   * Extract the gateway certificate, or "" if there was none in the 
   * response.
   * @param response response from the DT request.
   * @return a certificate string.
   */
  private String extractGatewayCertificate(final RequestDTResponseMessage response) {
    String cert = response.endpoint_public_cert;
    if (cert == null) {
      cert = "";
    }
    return cert;
  }

  /**
   * Get the token from the response -includes a check for a null/empty
   * token.
   * @param response response to a token request.
   * @return the token
   * @throws DelegationTokenIOException if invalid.
   */
  public String extractTokenFromResponse(final RequestDTResponseMessage response)
      throws DelegationTokenIOException {
    final String token = response.access_token;
    if (StringUtils.isEmpty(token)) {
      throw new DelegationTokenIOException(E_NO_KNOX_DELEGATION_TOKEN);
    }
    return token;
  }

  /**
   * The heavy lifting: collect an IDB token.
   * Maybe also: collect some AWS Credentials.
   * @param policy minimum policy to use, if known.
   * @param encryptionSecrets encryption secrets for the token.
   * @return the token identifier for the DT
   * @throws IOException failure to collect a DT.
   */
  @SuppressWarnings("OptionalGetWithoutIsPresent")
  @Override
  public AbstractS3ATokenIdentifier createTokenIdentifier(
      final Optional<RoleModel.Policy> policy,
      final EncryptionSecrets encryptionSecrets) throws IOException {
    long expiryTime;
    String knoxDT;
    String endpointCertificate;
    // the provider chain is only the IDB credentials.
    credentialProviders = new AWSCredentialProviderList();
    credentialProviders.add(new IDBCredentials());

    if (maybeRenewAccessToken()) {
      // if a token has been refreshed, recycle its parts.
      knoxDT = accessToken.get();
      expiryTime = accessTokenExpiresSeconds;
      endpointCertificate = gatewayCertificate;
    } else {
      // request a new DT so that it is valid
      final RequestDTResponseMessage response = requestNewAccessToken(false);
      knoxDT = extractTokenFromResponse(response);
      expiryTime = response.expiryTimeSeconds();
      endpointCertificate = extractGatewayCertificate(response);
    }
    // build the identifier
    String endpoint = idbClient.getCredentialsURL();
    IDBS3ATokenIdentifier identifier = new IDBS3ATokenIdentifier(
        IDB_TOKEN_KIND,
        getOwnerText(),
        getCanonicalUri(),
        knoxDT,
        expiryTime,
        collectAWSCredentialsForDelegation(),
        encryptionSecrets,
        Objects.toString(policy.orElse(null), ""),
        "Created from " + endpoint,
        System.currentTimeMillis(),
        getOwner().getUserName(),
        endpoint,
        endpointCertificate);
    LOG.debug("Created token identifier {}", identifier);
    return identifier;
  }

  /**
   * Return the unbonded credentials.
   * @return a provider list
   * @throws IOException failure
   * @throws PathAccessDeniedException if there is no username.
   */
  @Override
  public AWSCredentialProviderList deployUnbonded()
      throws IOException {
    // create the client
    idbClient = createFullIDBClient(getConfig(), getOwner());

    S3AFileSystem fs = getFileSystem();
    String bucket = fs.getBucket();
    Configuration conf = getConfig();
    // set up provider chain to fallback
    credentialProviders = new AWSCredentialProviderList();
    credentialProviders.add(new IDBCredentials());

    KnoxSession session = null;
    // delegation tokens are typically only collected in
    // kerberized scenarios. However, we may find some testing
    // or client side scenarios where it will make more sense to
    // use username and password to acquire the DT from IDBroker.
    String credentialsType = conf.get(IDBROKER_CREDENTIALS_TYPE.getPropertyName(), IDBROKER_CREDENTIALS_TYPE.getDefaultValue() );
    LOG.debug("IDBroker credentials type is {}", credentialsType);
    boolean dtViaUsernamePassword = credentialsType.equals(IDBConstants.IDBROKER_CREDENTIALS_BASIC_AUTH);

    String auth = conf.get(IDBConstants.HADOOP_SECURITY_AUTHENTICATION, IDBConstants.HADOOP_AUTH_SIMPLE);
    boolean isSimpleAuth = IDBConstants.HADOOP_AUTH_SIMPLE.equalsIgnoreCase(auth);
    if (dtViaUsernamePassword || isSimpleAuth) {
      LOG.debug("Authenticating with IDBroker via username and password");

      // TODO: check whether we want to use Knox token sessions
      // with JWT bearer token from the cached knox token to acquire
      // a DT for IDBroker use.

      String username = S3AUtils.lookupPassword(bucket, conf, IDBROKER_USERNAME.getPropertyName());
      String errorPrefix = dtViaUsernamePassword
          ? "Authentication with username and password enabled"
          : "No kerberos session -falling back to username and password";
      if (StringUtils.isEmpty(username)) {
        throw new IOException(errorPrefix +
            " -missing configuration option: " + IDBROKER_USERNAME.getPropertyName());
      }
      String password = S3AUtils.lookupPassword(bucket, conf, IDBROKER_PASSWORD.getPropertyName());
      if (StringUtils.isEmpty(password)) {
        throw new IOException(errorPrefix +
            " -missing configuration option: " + IDBROKER_PASSWORD.getPropertyName());
      }
      loginSecrets = Optional.of(Pair.of(username, password));
      loginSessionOrigin = "local login credentials";
      session = idbClient.knoxSessionFromSecrets(username, password);
    } else if (auth.equalsIgnoreCase("kerberos")) {
      LOG.debug("Authenticating with IDBroker with Kerberos");
      loginSessionOrigin = "local kerberos login";
      try {
        session = getOwner().doAs(new PrivilegedExceptionAction<KnoxSession>() {
          @Override
          public KnoxSession run() throws Exception {
            return idbClient.knoxSessionFromKerberos();
          }
        });
      } catch (InterruptedException e) {
        throw (IOException)new InterruptedIOException(e.toString()).initCause(e);
      }
    } else {
      // no match on either option
      // Current;
      LOG.warn("Unknown IDBroker authentication mechanism: \"{}\"",  auth);
    }

    collectAwsCredentials = conf.getBoolean(IDBROKER_INIT_CAB_CREDENTIALS.getPropertyName(), Boolean.valueOf(IDBROKER_INIT_CAB_CREDENTIALS.getDefaultValue()));
    loginSession = Optional.ofNullable(session);
    // set the expiry time to zero
    accessTokenExpiresSeconds = 0;
    // then ask for a token
    maybeRenewAccessToken();
    return credentialProviders;
  }

  /**
   * Bind to the token identifier.
   * @param retrievedIdentifier the unmarshalled data
   * @return the credential provider to use.
   * @throws IOException failure to retrieve a knox token.
   */
  @Override
  public AWSCredentialProviderList bindToTokenIdentifier(
      final AbstractS3ATokenIdentifier retrievedIdentifier) throws IOException {
    // create the client
    LOG.debug("Binding to retrieved token");
    idbClient = createLightIDBClient(getConfig());

    IDBS3ATokenIdentifier tokenIdentifier =
        convertTokenIdentifier(retrievedIdentifier,
            IDBS3ATokenIdentifier.class);
    tokenIdentifier.validate();
    boundTokenIdentifier = Optional.of(tokenIdentifier);
    String token = tokenIdentifier.getAccessToken();
    accessToken = Optional.of(token);
    accessTokenExpiresSeconds = tokenIdentifier.getExpiryTime();
    marshalledCredentials = extractMarshalledCredentials(tokenIdentifier);
    String endpointCert = tokenIdentifier.getCertificate();
    if (!endpointCert.isEmpty()) {
      gatewayCertificate = endpointCert;
      LOG.debug("Using Cloud Access Broker public cert from delegation token");
    }
    awsCredentialSession = Optional.of(
        idbClient.cloudSessionFromDelegationToken(token, gatewayCertificate));
    credentialProviders = new AWSCredentialProviderList();
    credentialProviders.add(new IDBCredentials());
    LOG.debug("Renewing AWS Credentials if needed");
    if (maybeResetAWSCredentials()) {
      LOG.debug("New AWS credentials will be requested");
    }
    return credentialProviders;
  }

  /**
   * Create an empty identifier for unmarshalling.
   * @return an empty identifier.
   */
  @Override
  public IDBS3ATokenIdentifier createEmptyIdentifier() {
    return new IDBS3ATokenIdentifier();
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(
        "IDBDelegationTokenBinding{");
    sb.append("marshalledCredentials=").append(
        marshalledCredentials.map(Objects::toString).orElse("<unset>"));
    sb.append(", accessToken=").append(accessToken.toString());
    sb.append(", hasLogin=").append(loginSession.isPresent());
    sb.append(", hasDtSession=").append(awsCredentialSession.isPresent());
    sb.append('}');
    return sb.toString();
  }

  /**
   * Using the existing login session, request a new access token.
   * @return the response of the request
   * @throws DelegationTokenIOException not logged in.
   * @throws IOException IO failure
   * @param hasExpired
   */
  private RequestDTResponseMessage requestNewAccessToken(final boolean hasExpired)
      throws IOException {
    KnoxSession session = loginSession.orElseThrow(
        () -> {
          String tokenInfo = boundTokenIdentifier.map(
              IDBS3ATokenIdentifier::errorMessageString).orElse("");
          String message = hasExpired
              ? String.format(E_NO_ACQUIRE_TOKEN_WHEN_HAS_EXPIRED, tokenInfo)
              : String.format(E_NO_ACQUIRE_TOKEN_FROM_TOKEN, tokenInfo);
          return new DelegationTokenIOException(message);
        });
    // request a token
    return idbClient.requestKnoxDelegationToken(session, loginSessionOrigin,
        getCanonicalUri());
  }

  /**
   * If a new access token needed, collect one and bond to it.
   * @return true iff a new access token was acquired.
   * @throws IOException if a token could not be requested.
   */
  private boolean maybeRenewAccessToken() throws IOException {
    if (hasExpired(accessTokenExpiresSeconds)) {
      boolean initialRequest = accessTokenExpiresSeconds == 0;
      LOG.debug(initialRequest
          ? "Requesting initial access token"
          : "Current access token has expired: requesting a new one");
      bondToRequestedToken(requestNewAccessToken(!initialRequest));
      return true;
    } else {
      return false;
    }
  }

  /**
   * Return existing marshalled credentials or collect new ones.
   * This method implements our policy about whether to include
   * AWS credentials in a DT, and/or whether and when to collect new ones
   * versus return any existing set.
   * @return Possibly empty credentials.
   * @throws IOException failure to fetch new credentials.
   */
  private MarshalledCredentials collectAWSCredentialsForDelegation()
      throws IOException {
    return collectAwsCredentials
        ? collectAWSCredentials()
        : MarshalledCredentials.empty();
  }

  /**
   * Return existing marshalled credentials or collect new ones.
   * @return the credentials.
   * @throws IOException failure to fetch new credentials.
   */
  @SuppressWarnings("OptionalGetWithoutIsPresent")
  private synchronized MarshalledCredentials collectAWSCredentials()
      throws IOException {
    if (maybeResetAWSCredentials()) {
      // no marshalled creds => Talk to IDB
      updateAWSCredentials();
    }
    return marshalledCredentials.get();
  }

  /**
   * Ask Knox for some AWS credentials and save in the
   * {@link #marshalledCredentials} field.
   * @throws IOException failure.
   */
  @VisibleForTesting
  synchronized void updateAWSCredentials() throws IOException {
    marshalledCredentials = Optional.of(
        fetchMarshalledAWSCredentials(
            idbClient,
            awsCredentialSession.orElseThrow(
                () -> new DelegationTokenIOException(E_NO_SESSION_TO_KNOX_AWS))));
  }

  /**
   * If we have AWS credentials, check for expiration and
   * clear the credentials field if they have expired.
   * @return true if credentials are required because
   * they are missing or expired.
   */
  @VisibleForTesting
  synchronized Boolean maybeResetAWSCredentials() {
    if (areAWSCredentialsNeeded()) {
      resetAWSCredentials();
      return true;
    }
    return false;
  }

  /**
   * Predicate: are AWS Credentials needed.
   * @return true if there are no credentials, or if there are none.
   */
  private boolean areAWSCredentialsNeeded() {
    return marshalledCredentials.map(
        c -> clock.hasExpired(c.getExpirationDateTime())).orElse(true);
  }

  /**
   * Reset the AWS credentials so they will be retrieved
   * the next time any are requested.
   */
  @VisibleForTesting
  synchronized void resetAWSCredentials() {
    marshalledCredentials = Optional.empty();
  }

  @VisibleForTesting
  UTCClock getClock() {
    return clock;
  }

  @VisibleForTesting
  void setClock(final UTCClock clock) {
    this.clock = clock;
  }

  /**
   * Has a time expired?
   * @param seconds expiry time.
   * @return true if the token is expired relative to the clock.
   */
  @VisibleForTesting
  boolean hasExpired(long seconds) {
    return clock.hasExpired(UTCClock.secondsToDateTime(seconds));
  }

  public Optional<String> getAccessToken() {
    return accessToken;
  }

  public long getAccessTokenExpiresSeconds() {
    return accessTokenExpiresSeconds;
  }

  /**
   * Iff the marshalled creds are non-empty they turned into AWS credentials.
   * @param tokenIdentifier token identifier
   * @return the credentials, if there are any.
   */
  @VisibleForTesting
  static Optional<MarshalledCredentials> extractMarshalledCredentials(
      final IDBS3ATokenIdentifier tokenIdentifier) {
    MarshalledCredentials incomingAwsCreds
        = tokenIdentifier.getMarshalledCredentials();
    // discard them if invalid
    return incomingAwsCreds.isValid(
        MarshalledCredentials.CredentialTypeRequired.SessionOnly)
        ? Optional.of(incomingAwsCreds)
        : Optional.empty();
  }
  
  /**
   * Provide AWS Credentials from any retrieved set.
   */
  private class IDBCredentials implements AWSCredentialsProvider {

    @Override
    public AWSCredentials getCredentials() {
      try {
        return fetchCredentials();
      } catch (IOException e) {
        LOG.warn("Failed to fetch credentials: " + e);
        LOG.debug("Failed to fetch credentials: ", e);
        throw new NoAuthWithAWSException(e.getMessage(), e);
      }
    }

    @Override
    public void refresh() {
      // marks things a clear
      resetAWSCredentials();
    }

    protected AWSCredentials fetchCredentials() throws IOException {
      // if we have AWS credentials,
      // trigger a knox token renewal if required.
      maybeRenewAccessToken();
      return MarshalledCredentialBinding.toAWSCredentials(
          collectAWSCredentials(),
          MarshalledCredentials.CredentialTypeRequired.SessionOnly,
          COMPONENT_NAME);
    }

    @Override
    public String toString() {
      return "IDBCredentials for " + IDBDelegationTokenBinding.super.toString();
    }
  }

}

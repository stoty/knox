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

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.google.common.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.PathAccessDeniedException;
import org.apache.hadoop.fs.s3a.AWSCredentialProviderList;
import org.apache.hadoop.fs.s3a.CredentialInitializationException;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.S3AUtils;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentialBinding;
import org.apache.hadoop.fs.s3a.auth.RoleModel;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractDelegationTokenBinding;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.fs.s3a.auth.delegation.DelegationTokenIOException;
import org.apache.hadoop.fs.s3a.auth.delegation.EncryptionSecrets;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.IdentityBrokerClient;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;

import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDBROKER_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDBROKER_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDB_TOKEN_KIND;

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

  private static final String FS_S3A_IDBROKER_CREDENTIALS_TYPE = "fs.s3a.idbroker.credentials.type";

  private static final String HADOOP_SECURITY_AUTHENTICATION = "hadoop.security.authentication";

  public static final String E_NO_RENEW_TOKEN
      = "Cannot renew a delegation token";

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
  private IDBClient idbClient;

  private UTCClock clock = new UTCClock();

  /**
   * This is a connection to the knox DT issuing endpoint.
   * it is non-empty if this binding was instantiated without
   * a delegation token, that is: new DTs can be requested.
   * Will be set in {@link #deployUnbonded()}.
   */
  private Optional<KnoxSession> loginSession = Optional.empty();

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
  private Optional<KnoxSession> awsCredentialSession = Optional.empty();

  /**
   * Expiry time for the DT.
   */
  private long accessTokenExpiresSeconds;

  /**
   * Login information; if empty: no login.
   */
  private Optional<Pair<String, String>> loginSecrets = Optional.empty();

  /**
   * Reflection-based constructor.
   */
  public IDBDelegationTokenBinding() {
    this(NAME, IDBConstants.IDB_TOKEN_KIND);
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
   * This exists while IDBClient keeps out of the S3A DT dependencies. 
   * @param dtSession session to use.
   * @return AWS credentials.
   * @throws IOException failure.
   */
  @VisibleForTesting
  static MarshalledCredentials fetchMarshalledAWSCredentials(
      IdentityBrokerClient client,
      KnoxSession dtSession)
      throws IOException {
    final MarshalledCredentials received =
        client.fetchAWSCredentials(dtSession);
    final MarshalledCredentials marshalled = new MarshalledCredentials(
        received.getAccessKey(),
        received.getSecretKey(),
        received.getSessionToken());
    marshalled.setExpiration(received.getExpiration());
    marshalled.setRoleARN(received.getRoleARN());
    return marshalled;
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
    awsCredentialSession = Optional.of(idbClient.cloudSessionFromDT(token));
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
    // the provider chain is only the IDB credentials.
    credentialProviders = new AWSCredentialProviderList();
    credentialProviders.add(new IDBCredentials());
    
    if (maybeRenewAccessToken()) {
      // if a token has been refreshed, recycle its parts.
      knoxDT = accessToken.get();
      expiryTime = accessTokenExpiresSeconds;
    } else {
      // request a new DT so that it is valid
      RequestDTResponseMessage response = requestNewAccessToken();
      knoxDT = extractTokenFromResponse(response);
      expiryTime = response.expiryTimeSeconds();
    }
    // build the identifier
    IDBS3ATokenIdentifier identifier = new IDBS3ATokenIdentifier(
        IDB_TOKEN_KIND,
        getOwnerText(),
        getCanonicalUri(),
        knoxDT,
        expiryTime,
        collectAWSCredentialsForDelegation(),
        encryptionSecrets,
        policy.map(Object::toString).orElse(""),
        "Created from " + idbClient.getGateway());
    LOG.debug("Created token identifier {}", identifier);
    return identifier;
  }

  /*
  Client logged in with IDB (user, pass)
    - log in as below, issue DTs on demand.
    
  Client logged in with Kerberos
    -new knoxDtSession setup; issue DTs on demand.
    
  Service code with no Kerberos nor (user, pass)
    -bypass IDB, issue DTs which are *empty*.
    Far end will be, what? 
    
  Service code with Kerberos (e.g hive/REALM)
    -? 
  
   Alice  alice.ex    core-site.xml + Kinit
   Bob    bob.ex      core-site.xml + Kinit
   Hive   node1       core-site.xml + hive-site.xml + keytab
   
   workers node1...node-2  core-site.xml + any DTs
     r/w to s3a://logs/
  
   */
  /**
   * Return the unbonded credentials.
   * @return a provider list
   * @throws IOException failure
   * @throws PathAccessDeniedException if there is no username.
   */
  @Override
  public AWSCredentialProviderList deployUnbonded()
      throws IOException {
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
    boolean dtViaUsernamePassword = conf.get(
        FS_S3A_IDBROKER_CREDENTIALS_TYPE, "kerberos").
        equals("username-password");

    String auth = conf.get(HADOOP_SECURITY_AUTHENTICATION, "simple");
    
    if (dtViaUsernamePassword ||
        auth.equalsIgnoreCase("simple")) {

      // TODO: check whether we want to use Knox token sessions
      // with JWT bearer token from the cached knox token to acquire
      // a DT for IDBroker use.

      String username = S3AUtils.lookupPassword(bucket, conf,
          IDBROKER_USERNAME);
      String password = S3AUtils.lookupPassword(bucket, conf,
          IDBROKER_TRUSTSTORE_PASSWORD);
      if (StringUtils.isEmpty(username)) {
        username = IDBConstants.ADMIN_USER;
        password = IDBConstants.ADMIN_PASSWORD;
      }
      loginSecrets = Optional.of(Pair.of(username, password));
      session = idbClient.knoxDtSession(username, password);
    } else if (auth.equalsIgnoreCase("kerberos")) {
      session = idbClient.knoxDtSession();
    } else {
      // no match on either option
      // Current;
      
      LOG.warn("Unknown IDBroker auth mechanism: \"{}\"",  auth);
    }

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
    IDBS3ATokenIdentifier tokenIdentifier =
        convertTokenIdentifier(retrievedIdentifier,
            IDBS3ATokenIdentifier.class);
    boundTokenIdentifier = Optional.of(tokenIdentifier);
    String token = tokenIdentifier.getAccessToken();
    accessToken = Optional.of(token);
    accessTokenExpiresSeconds = tokenIdentifier.getExpiryTime();
    // iff the marshalled creds are non-empty they turned into AWS credentials.
    MarshalledCredentials incomingAwsCreds
        = tokenIdentifier.getMarshalledCredentials();
    // discard them if invalid
    this.marshalledCredentials = incomingAwsCreds.isValid(
        MarshalledCredentials.CredentialTypeRequired.SessionOnly)
        ? Optional.of(incomingAwsCreds)
        : Optional.empty();
    awsCredentialSession = Optional.of(idbClient.cloudSessionFromDT(token));
    credentialProviders =
        new AWSCredentialProviderList();
    credentialProviders.add(new IDBCredentials());
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
   * Service startL create the IDBClient based on config.
   * @throws Exception failure
   */
  @Override
  protected void serviceStart() throws Exception {
    super.serviceStart();
    // create the client
    idbClient = new IDBClient(getConfig());
  }

  /**
   * Using the existing login session, request a new access token.
   * @return the response of the request
   * @throws DelegationTokenIOException not logged in.
   * @throws IOException IO failure
   */
  private RequestDTResponseMessage requestNewAccessToken() throws IOException {
    KnoxSession session = loginSession.orElseThrow(
        () -> new DelegationTokenIOException(E_NO_RENEW_TOKEN));
    // request a token
    return idbClient.requestKnoxDelegationToken(session);
  }

  /**
   * If a new access token needed, collect one.
   * This does not guarantee that one can be requested, only that
   * the current token has expired.
   * @return true iff a new access token was requested.
   */
  private boolean maybeRenewAccessToken() throws IOException {
    if (hasExpired(accessTokenExpiresSeconds)) {
      LOG.debug(accessTokenExpiresSeconds == 0
          ? "Requesting initial access token"
          : "Current access token has expired: requesting a new one");
      bondToRequestedToken(requestNewAccessToken());
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
   * @return the credentials.
   * @throws IOException failure to fetch new credentials.
   */
  private MarshalledCredentials collectAWSCredentialsForDelegation()
      throws IOException {
    return collectAWSCredentials();
//    return MarshalledCredentials.empty();
  }

  /**
   * Return existing marshalled credentials or collect new ones.
   * @return the credentials.
   * @throws IOException failure to fetch new credentials.
   */
  @SuppressWarnings("OptionalGetWithoutIsPresent")
  private synchronized MarshalledCredentials collectAWSCredentials()
      throws IOException {
    if (needsAWSCredentials()) {
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
  synchronized Boolean needsAWSCredentials() {
    return marshalledCredentials.map(
        (c) -> {
          long expiration = c.getExpiration();
          if (expiration > 0 && hasExpired(expiration)) {
            LOG.info("Expiring current AWS credentials");
            resetAWSCredentials();
            return true;
          } else {
            return false;
          }
        }).orElse(true);
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
    return (seconds < TimeUnit.MILLISECONDS.toSeconds(clock.getTimeInMillis()));
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
        throw new CredentialInitializationException(e.getMessage(), e);
      }
    }

    @Override
    public void refresh() {
      // marks things a clear
      resetAWSCredentials();
    }

    protected AWSCredentials fetchCredentials() throws IOException {
      // if we have AWS credentials, 
      return MarshalledCredentialBinding.toAWSCredentials(
          collectAWSCredentials(),
          MarshalledCredentials.CredentialTypeRequired.SessionOnly,
          COMPONENT_NAME);
    }
  }


}

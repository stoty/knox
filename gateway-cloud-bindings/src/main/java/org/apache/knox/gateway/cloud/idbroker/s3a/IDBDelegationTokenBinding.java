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

import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.MESSAGE_FAILURE_TO_AUTHENTICATE_TO_IDB_DT;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.MESSAGE_FAILURE_TO_AUTHENTICATE_TO_IDB_KERBEROS;
import static org.apache.knox.gateway.cloud.idbroker.s3a.IDBS3AConstants.IDB_TOKEN_KIND;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBClient.createFullIDBClient;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBClient.createLightIDBClient;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_DT_EXPIRATION_OFFSET;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_INIT_CAB_CREDENTIALS;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.PathAccessDeniedException;
import org.apache.hadoop.fs.s3a.AWSCredentialProviderList;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentialBinding;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.NoAuthWithAWSException;
import org.apache.hadoop.fs.s3a.auth.RoleModel;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractDelegationTokenBinding;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.fs.s3a.auth.delegation.DelegationTokenIOException;
import org.apache.hadoop.fs.s3a.auth.delegation.EncryptionSecrets;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxToken;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxTokenMonitor;
import org.apache.knox.gateway.cloud.idbroker.common.UTCClock;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.util.Tokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

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

  private static final String E_NO_ACQUIRE_TOKEN_FROM_TOKEN
      = "Cannot acquire Knox token unless logged in; using %s";

  private static final String E_NO_ACQUIRE_TOKEN_WHEN_HAS_EXPIRED
      = "Knox token has expired; the current token is %s";

  private static final String E_NO_KNOX_DELEGATION_TOKEN
      = "No Knox token";

  private static final String E_NO_SESSION_TO_KNOX_AWS
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
  private static final String COMPONENT_NAME = NAME;

  /**
   * There's only one credential provider; this ensures that
   * its synchronized calls really do get locks.
   */
  private AWSCredentialProviderList credentialProviders;

  /**
   * Session credentials: initially empty.
   */
  private MarshalledCredentials marshalledCredentials;

  /**
   * Client connection, created in start.
   */
  private S3AIDBClient idbClient;

  private UTCClock clock = UTCClock.getClock();

  /**
   * The token identifier bound to in
   * {@link #bindToTokenIdentifier(AbstractS3ATokenIdentifier)}.
   */
  private IDBS3ATokenIdentifier boundTokenIdentifier;

  /**
   * Should AWS Credentials be collected when issuing a DT?
   */
  private boolean collectAwsCredentials = true;

  /**
   * The Knox token for this binding
   */
  private KnoxToken knoxToken;

  private KnoxTokenMonitor knoxTokenMonitor;

  private final Lock lock = new ReentrantLock(true);

  /**
   * Reflection-based constructor.
   */
  public IDBDelegationTokenBinding() {
    this(NAME, IDB_TOKEN_KIND);
  }

  /**
   * Constructor.
   *
   * @param name binding name
   * @param kind token kind.
   */
  public IDBDelegationTokenBinding(final String name, final Text kind) {
    super(name, kind);
  }

  /**
   * The configuration isn't available when the constructor is invoked, so this method must be called
   * before any attempt to use the KnoxTokenMonitor.
   */
  private void initKnoxTokenMonitor() {
    if (knoxTokenMonitor == null) {
      if (idbClient != null && idbClient.shouldInitKnoxTokenMonitor()) {
        knoxTokenMonitor = new KnoxTokenMonitor();
      }
    }
  }

  /**
   * Fetch the AWS credentials as a marshalled set of credentials.
   *
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
   *
   * @param response response from the DT request.
   * @throws IOException failure to get an AWS credential session
   */
  private void bondToRequestedToken(final RequestDTResponseMessage response)
      throws IOException {
    final String token = extractTokenFromResponse(response);

    // print a small bit of the secret
    LOG.info("Bonded to Knox token {}", Tokens.getTokenDisplayText(token));

    String gatewayCertificate = extractGatewayCertificate(response);
    if (gatewayCertificate.isEmpty()) {
      LOG.warn("No certificate provided by gateway: renewals will not work");
    }

    knoxToken = new KnoxToken("", token, response.token_type, response.expiryTimeSeconds(), gatewayCertificate);
    monitorKnoxToken();
  }

  /**
   * Extract the gateway certificate, or "" if there was none in the
   * response.
   *
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
   *
   * @param response response to a token request.
   * @return the token
   * @throws DelegationTokenIOException if invalid.
   */
  private String extractTokenFromResponse(final RequestDTResponseMessage response)
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
   *
   * @param policy            minimum policy to use, if known.
   * @param encryptionSecrets encryption secrets for the token.
   * @return the token identifier for the DT
   * @throws IOException failure to collect a DT.
   */
  @Override
  public AbstractS3ATokenIdentifier createTokenIdentifier(
      final Optional<RoleModel.Policy> policy,
      final EncryptionSecrets encryptionSecrets,
      final Text renewer) throws IOException {

    lock.lock();
    try {
      // the provider chain is only the IDB credentials.
      credentialProviders = new AWSCredentialProviderList();
      credentialProviders.add(new IDBCredentials());

      maybeRenewAccessToken("creating token identifier");

      final String knoxDT = knoxToken == null ?  "" : knoxToken.getAccessToken();
      final long expiryTime = knoxToken == null ?  0L : knoxToken.getExpiry();
      final String endpointCertificate = knoxToken == null ?  "" : knoxToken.getEndpointPublicCert();

      // build the identifier
      final String endpoint = idbClient.getCredentialsURL();
      IDBS3ATokenIdentifier identifier = new IDBS3ATokenIdentifier(
          IDB_TOKEN_KIND,
          getOwnerText(),
          renewer,
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
      LOG.info("Created token identifier {}", identifier);
      return identifier;
    } finally {
      lock.unlock();
    }
  }

  /**
   * Return the unbonded credentials.
   *
   * @return a provider list
   * @throws IOException               failure
   * @throws PathAccessDeniedException if there is no username.
   */
  @Override
  public AWSCredentialProviderList deployUnbonded() throws IOException {
    lock.lock();
    try {
      // create the client
      idbClient = createFullIDBClient(getConfig(), getOwner(), getFileSystem());

      Configuration conf = getConfig();
      // set up provider chain to fallback
      credentialProviders = new AWSCredentialProviderList();
      credentialProviders.add(new IDBCredentials());
      collectAwsCredentials = conf.getBoolean(IDBROKER_INIT_CAB_CREDENTIALS.getPropertyName(), Boolean.valueOf(IDBROKER_INIT_CAB_CREDENTIALS.getDefaultValue()));

      // set the expiry time to zero
      // then ask for a token
      maybeRenewAccessToken("deploying unbonded token");
      return credentialProviders;
    } finally {
      lock.unlock();
    }
  }

  /**
   * Bind to the token identifier.
   *
   * @param retrievedIdentifier the unmarshalled data
   * @return the credential provider to use.
   * @throws IOException failure to retrieve a knox token.
   */
  @Override
  public AWSCredentialProviderList bindToTokenIdentifier(final AbstractS3ATokenIdentifier retrievedIdentifier) throws IOException {
    lock.lock();
    try {
      LOG.info("Binding to retrieved Delegation Token identifier: " + retrievedIdentifier == null ? "N/A" : retrievedIdentifier.toString());
      // create the client
      idbClient = createLightIDBClient(getConfig(), getFileSystem());

      final IDBS3ATokenIdentifier tokenIdentifier = convertTokenIdentifier(retrievedIdentifier, IDBS3ATokenIdentifier.class);
      tokenIdentifier.validate();

      boundTokenIdentifier = tokenIdentifier;
      marshalledCredentials = extractMarshalledCredentials(tokenIdentifier);

      knoxToken = new KnoxToken(tokenIdentifier.getOrigin(), tokenIdentifier.getAccessToken(), tokenIdentifier.getExpiryTime(), tokenIdentifier.getCertificate());

      monitorKnoxToken();

      if (StringUtils.isNotEmpty(knoxToken.getEndpointPublicCert())) {
        LOG.debug("Using Cloud Access Broker public cert from delegation token");
      }

      credentialProviders = new AWSCredentialProviderList();
      credentialProviders.add(new IDBCredentials());
      LOG.debug("Renewing AWS Credentials if needed");
      if (maybeResetAWSCredentials()) {
        LOG.info("New AWS credentials will be requested");
      }
      return credentialProviders;
    } finally {
      lock.unlock();
    }
  }

  /**
   * Create an empty identifier for unmarshalling.
   *
   * @return an empty identifier.
   */
  @Override
  public IDBS3ATokenIdentifier createEmptyIdentifier() {
    return new IDBS3ATokenIdentifier();
  }

  @Override
  public String toString() {
    lock.lock();
    try {
      return "IDBDelegationTokenBinding{" + "marshaledCredentials=" + Objects.toString(marshalledCredentials, "<unset>") + ", accessToken="
          + Objects.toString(knoxToken, "<unset>") + '}';
    } finally {
      lock.unlock();
    }
  }

  /**
   * Using the existing login session, request a new access token.
   *
   * @param hasExpired true if the current token has expired; false if there was no current token
   * @return the response of the request
   * @throws DelegationTokenIOException not logged in.
   * @throws IOException                IO failure
   */
  private RequestDTResponseMessage requestNewKnoxToken(final boolean hasExpired)
      throws IOException {

    Pair<KnoxSession, String> sessionPair = getNewKnoxDelegationTokenSession();

    KnoxSession session = sessionPair.getLeft();

    if (session == null) {
      String tokenInfo = (boundTokenIdentifier == null) ? "" : boundTokenIdentifier.errorMessageString();

      String message = hasExpired
          ? String.format(Locale.ROOT, E_NO_ACQUIRE_TOKEN_WHEN_HAS_EXPIRED, tokenInfo)
          : String.format(Locale.ROOT, E_NO_ACQUIRE_TOKEN_FROM_TOKEN, tokenInfo);
      throw new DelegationTokenIOException(message);
    }

    String origin = sessionPair.getRight();

    try {
      // request a token
      return idbClient.requestKnoxDelegationToken(session, origin, getCanonicalUri());
    } finally {
      IOUtils.cleanupWithLogger(LOG, session);
    }
  }

  private Pair<KnoxSession, String> getNewKnoxDelegationTokenSession() throws IOException {
    LOG.debug("Attempting to create a Knox delegation token session using local credentials (kerberos, simple)");
    Pair<KnoxSession, String> sessionDetails = idbClient.createKnoxDTSession(getConfig());
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

  /**
   * If a new access token needed, collect one and bond to it.
   *
   * @throws IOException if a token could not be requested.
   */
  private void maybeRenewAccessToken(String source) throws IOException {
    LOG.info("Maybe renewing Knox Token when {}", source);
    if (knoxToken == null) {
      LOG.info("There is no Knox Token available, fetching one from IDBroker...");
      getNewKnoxToken(true);
    } else {
      LOG.info("Using existing Knox Token: " + Tokens.getTokenDisplayText(knoxToken.getAccessToken()));
    }
  }

  private void getNewKnoxToken(boolean hasExpired) throws IOException {
    final RequestDTResponseMessage message = requestNewKnoxToken(!hasExpired);

    if (message != null) {
      bondToRequestedToken(message);
    }
  }

  /**
   * Return existing marshalled credentials or collect new ones.
   * This method implements our policy about whether to include
   * AWS credentials in a DT, and/or whether and when to collect new ones
   * versus return any existing set.
   *
   * @return Possibly empty credentials.
   * @throws IOException failure to fetch new credentials.
   */
  private MarshalledCredentials collectAWSCredentialsForDelegation() throws IOException {
    return collectAwsCredentials
        ? collectAWSCredentials()
        : MarshalledCredentials.empty();
  }

  /**
   * Return existing marshalled credentials or collect new ones.
   *
   * @return the credentials.
   * @throws IOException failure to fetch new credentials.
   */
  private MarshalledCredentials collectAWSCredentials() throws IOException {
    if (maybeResetAWSCredentials()) {
      // no marshalled creds => Talk to IDB
      updateAWSCredentials();
    }
    LOG.debug("AWS credentials: {}", marshalledCredentials.toString());
    return marshalledCredentials;
  }

  /**
   * Ask Knox for some AWS credentials and save in the
   * {@link #marshalledCredentials} field.
   *
   * @throws IOException failure.
   */
  @VisibleForTesting
  void updateAWSCredentials() throws IOException {
    LOG.debug("Requesting AWS credentials from IDBroker");
    CloudAccessBrokerSession knoxCABSession = idbClient.createKnoxCABSession(knoxToken);
    if (knoxCABSession == null) {
      throw new DelegationTokenIOException(E_NO_SESSION_TO_KNOX_AWS);
    }
    marshalledCredentials = fetchMarshalledAWSCredentials(idbClient, knoxCABSession);
  }

  /**
   * If we have AWS credentials, check for expiration and
   * clear the credentials field if they have expired.
   *
   * @return true if credentials are required because
   * they are missing or expired.
   */
  @VisibleForTesting
  Boolean maybeResetAWSCredentials() {
    if (areAWSCredentialsNeeded()) {
      resetAWSCredentials();
      return true;
    }
    return false;
  }

  /**
   * Predicate: are AWS Credentials needed.
   *
   * @return true if there are no credentials, or if there are none.
   */
  private boolean areAWSCredentialsNeeded() {
    LOG.debug("Checking if AWS credentials are needed");
    LOG.debug("Clock current time: {}", clock.getCurrentTime());
    if(marshalledCredentials == null) {
      return true;
    } else {
      Optional<OffsetDateTime> expirationDateTime = marshalledCredentials.getExpirationDateTime();
      LOG.debug("Credential expiration time: {}", expirationDateTime);
      return clock.hasExpired(expirationDateTime);
    }
  }

  /**
   * Reset the AWS credentials so they will be retrieved
   * the next time any are requested.
   */
  @VisibleForTesting
  void resetAWSCredentials() {
    LOG.debug("Resetting AWS credentials");
    marshalledCredentials = null;
  }

  /**
   * Iff the marshalled creds are non-empty they turned into AWS credentials.
   *
   * @param tokenIdentifier token identifier
   * @return the credentials, if there are any.
   */
  @VisibleForTesting
  static MarshalledCredentials extractMarshalledCredentials(
      final IDBS3ATokenIdentifier tokenIdentifier) {
    MarshalledCredentials incomingAwsCreds
        = tokenIdentifier.getMarshalledCredentials();
    // discard them if invalid

    return incomingAwsCreds.isValid(MarshalledCredentials.CredentialTypeRequired.SessionOnly)
        ? incomingAwsCreds
        : null;
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
        LOG.warn("Failed to fetch credentials: " + e.getMessage());
        LOG.debug("Failed to fetch credentials: ", e);
        throw new NoAuthWithAWSException(e.getMessage(), e);
      }
    }

    @Override
    public void refresh() {
      // marks things a clear
      resetAWSCredentials();
    }

    AWSCredentials fetchCredentials() throws IOException {
      lock.lock();
      try {
        // if we have AWS credentials,
        // trigger a knox token renewal if required.
        maybeRenewAccessToken("fetching AWS credentials");
        return MarshalledCredentialBinding.toAWSCredentials(
            collectAWSCredentials(),
            MarshalledCredentials.CredentialTypeRequired.SessionOnly,
            COMPONENT_NAME);
      } finally {
        lock.unlock();
      }
    }

    @Override
    public String toString() {
      return "IDBCredentials for " + IDBDelegationTokenBinding.super.toString();
    }
  }

  @Override
  protected void serviceStop() throws Exception {
    // If the Knox token monitor was initialized, shut it down
    stopKnoxTokenMonitor();
    super.serviceStop();
  }

  private void monitorKnoxToken() {
    // Maybe initialize the Knox token monitor
    initKnoxTokenMonitor();

    // Only start monitoring the token if the token monitor has been initialized
    if (knoxTokenMonitor != null) {
      long knoxTokenExpirationOffset =
              getConfig().getLong(IDBROKER_DT_EXPIRATION_OFFSET.getPropertyName(),
                                  Long.parseLong(IDBROKER_DT_EXPIRATION_OFFSET.getDefaultValue()));

      knoxTokenMonitor.monitorKnoxToken(knoxToken, knoxTokenExpirationOffset, new GetKnoxTokenCommand());
    }
  }

  private void stopKnoxTokenMonitor() {
    if (knoxTokenMonitor != null) {
      knoxTokenMonitor.shutdown();
    }
  }

  private class GetKnoxTokenCommand implements KnoxTokenMonitor.GetKnoxTokenCommand {
    @Override
    public void execute(KnoxToken knoxToken) throws IOException {
      lock.lock();
      try {
        getNewKnoxToken(knoxToken != null);
      } finally {
        lock.unlock();
      }
    }
  }
}

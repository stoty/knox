/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.cloud.idbroker.google;

import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.MESSAGE_FAILURE_TO_AUTHENTICATE_TO_IDB_DT;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.MESSAGE_FAILURE_TO_AUTHENTICATE_TO_IDB_KERBEROS;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_DT_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_DT_EXPIRATION_OFFSET;

import com.google.cloud.hadoop.fs.gcs.auth.AbstractDelegationTokenBinding;
import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import com.google.cloud.hadoop.util.AccessTokenProvider;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
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
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class CABDelegationTokenBinding extends AbstractDelegationTokenBinding {

  protected static final Logger LOG =
      LoggerFactory.getLogger(CABDelegationTokenBinding.class);

  static final String E_INVALID_DT_RESPONSE =
      "Invalid delegation token response";

  static final String E_FAILED_DT_SESSION =
      "Error establishing session with delegation token provider";

  static final String E_FAILED_CLOUD_SESSION =
      "Error establishing session with Cloud Access Broker credential provider";

  static final String E_NO_SESSION_TO_KNOX_CREDS
      = "No session with Knox credential endpoint";

  static final String E_MISSING_DT_USERNAME_CONFIG =
      "Missing Cloud Access Broker delegation token username configuration"
          + " in " + CONFIG_DT_USERNAME;


  protected IDBClient<AccessTokenProvider.AccessToken> cabClient;

  /**
   * This is the knox token.
   */
  private KnoxToken knoxToken;

  private KnoxTokenMonitor knoxTokenMonitor;

  private final Lock lock = new ReentrantLock(true);

  private GoogleTempCredentials marshalledCredentials;

  private TokenProvider accessTokenProvider;

  public CABDelegationTokenBinding() {
    super("IDBDelegationTokenBinding", CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND);
  }

  /**
   * The configuration isn't available when the constructor is invoked, so this method must be called
   * before any attempt to use the KnoxTokenMonitor.
   */
  private void initKnoxTokenMonitor() {
    if (knoxTokenMonitor == null) {
      IDBClient<AccessTokenProvider.AccessToken> client = getClient();
      if (client != null && client.shouldInitKnoxTokenMonitor()) {
        knoxTokenMonitor = new KnoxTokenMonitor();
      }
    }
  }

  @Override
  protected void serviceStart() throws Exception {
    super.serviceStart();
  }

  @Override
  protected void serviceStop() throws Exception {
    stopKnoxTokenMonitor();
    super.serviceStop();
  }

  private void stopKnoxTokenMonitor() {
    if (knoxTokenMonitor != null) {
      knoxTokenMonitor.shutdown();
    }
  }

  IDBClient<AccessTokenProvider.AccessToken> getClient() {
    lock.lock();
    try {
      if (cabClient == null) {
        try {
          cabClient = CABUtils.newClient(getConf(), UserGroupInformation.getCurrentUser());
          if (cabClient == null) { // This should never happen, but leaving this message for debugging CDPD-18470
            LOG.error("cabClient has not been initialized.");
          }
        } catch (Throwable t) {
          LOG.error("Error creating new IDBroker client for Google Cloud Platform.", t);
        }
      }

      return cabClient;
    } finally {
      lock.unlock();
    }
  }

  Configuration getConf() {
    return getFileSystem().getConf();
  }


  /**
   * Return the unbonded credentials.
   *
   * @throws IOException failure
   */
  @Override
  public AccessTokenProvider deployUnbonded() throws IOException {
    lock.lock();
    try {
      maybeRenewAccessToken();
      return getAccessTokenProvider();
    } finally {
      lock.unlock();
    }
  }

  TokenProvider getAccessTokenProvider() {
    if (accessTokenProvider == null) {
      LOG.debug("No existing accessTokenProvider");
      String gcpToken = null;
      long gcpTokenExp = -1;

      if (marshalledCredentials != null) {
        LOG.debug("Using existing marshalled credentials");
        gcpToken = marshalledCredentials.getToken();
        gcpTokenExp = marshalledCredentials.getExpiration();
      }

      LOG.debug("Creating new accessTokenProvider");
      accessTokenProvider = new CloudAccessBrokerTokenProvider(getClient(), knoxToken, gcpToken, gcpTokenExp);
    }

    return accessTokenProvider;
  }

  /**
   * Create a Cloud Access Broker token, possibly including an initial set of GCP credentials.
   *
   * @return the token identifier for the DT
   * @throws IOException failure to collect a DT.
   */
  @Override
  public DelegationTokenIdentifier createTokenIdentifier(Text renewer) throws IOException {
    lock.lock();
    try {
      final String tokenType = null;
      final String targetURL = CABUtils.getCloudAccessBrokerURL(getConf(), getClient().getGatewayAddress());

      maybeRenewAccessToken();

      final String knoxDT = knoxToken == null ?  "" : knoxToken.getAccessToken();
      final long expiryTime = knoxToken == null ?  0L : knoxToken.getExpiry();
      final String endpointCertificate = knoxToken == null ?  "" : knoxToken.getEndpointPublicCert();
      final boolean managed = knoxToken == null ? false : knoxToken.isManaged();

      final GoogleTempCredentials gcpCredentials;
      if (getConf().getBoolean(CloudAccessBrokerBindingConstants.CONFIG_INIT_CLOUD_CREDS, true)) {
        gcpCredentials = collectGCPCredentials();
      } else {
        gcpCredentials = new GoogleTempCredentials();
      }

      // build the identifier
      final DelegationTokenIdentifier identifier = new CABGCPTokenIdentifier(getKind(),
          getOwnerText(UserGroupInformation.getCurrentUser()),
          renewer,
          getCanonicalUri(),
          knoxDT,
          expiryTime,
          tokenType,
          targetURL,
          endpointCertificate,
          gcpCredentials,
          "Created from " + getClient().getGatewayAddress(),
          managed);

      LOG.info("Created delegation token identifier {}", identifier);

      return identifier;
    } finally {
      lock.unlock();
    }
  }

  @Override
  public DelegationTokenIdentifier createTokenIdentifier() throws IOException {
    return createTokenIdentifier(null);
  }

  @Override
  public DelegationTokenIdentifier createEmptyIdentifier() {
    return null;
  }

  /**
   * If a new access token needed, collect one.
   * This does not guarantee that one can be requested, only that
   * the current token has expired.
   */
  private void maybeRenewAccessToken() throws IOException {
    if (knoxToken == null || StringUtils.isBlank(knoxToken.getAccessToken())) {
      if (getClient().shouldExcludeUserFromGettingKnoxToken()) {
        LOG.info("'{}' is excluded from getting Knox Token from IDBroker", getClient().getOwnerUserName());
      } else {
        LOG.info("There is no Knox Token available, fetching one from IDBroker...");
        getNewKnoxToken();
      }
    } else {
      LOG.debug("Using existing Knox Token: " + Tokens.getTokenDisplayText(knoxToken.getAccessToken()));
    }
  }

  private void getNewKnoxToken() throws IOException {
    final Pair<RequestDTResponseMessage, String> message = requestDelegationToken();

    if (message != null) {
      bondToRequestedToken(message);
    }
  }

  /**
   * Has a time expired?
   *
   * @param seconds expiry time.
   * @return true if the token is expired relative to the clock.
   */
  private boolean hasExpired(long seconds) {
    return (seconds < TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis())); // TODO: PJZ: threshold adjustment?
  }


  @Override
  public AccessTokenProvider bindToTokenIdentifier(DelegationTokenIdentifier retrievedIdentifier)
      throws IOException {
    lock.lock();
    try {
      LOG.info("Binding to retrieved Delegation Token identifier: " + retrievedIdentifier == null ? "N/A" : retrievedIdentifier.toString());
      CABGCPTokenIdentifier tokenIdentifier = convertTokenIdentifier(retrievedIdentifier, CABGCPTokenIdentifier.class);

      final String endpointCert = tokenIdentifier.getCertificate();
      if (endpointCert != null) {
        LOG.debug("Using Cloud Access Broker public cert from delegation token");
      }

      knoxToken = new KnoxToken("origin", tokenIdentifier.getAccessToken(), tokenIdentifier.getTokenType(), tokenIdentifier.getExpiryTime(), endpointCert, tokenIdentifier.isManaged());

      monitorKnoxToken();

      // GCP credentials
      marshalledCredentials = tokenIdentifier.getMarshalledCredentials();
      LOG.debug("Marshalled GCP credentials: " + marshalledCredentials.toString());

      final TokenProvider tokenProvider = getAccessTokenProvider();
      tokenProvider.updateDelegationToken(knoxToken);
      return tokenProvider;
    } finally {
      lock.unlock();
    }
  }

  /**
   * Bond to the response of a knox login + DT request.
   * This doesn't kick off the first retrieval of secrets.
   *
   * @param response response from the DT request.
   * @throws IOException failure to get an GCP credential session
   */
  private void bondToRequestedToken(final Pair<RequestDTResponseMessage, String> response) throws IOException {
    if ((response == null) || (response.getLeft() == null)) {
      throw new DelegationTokenIOException(E_INVALID_DT_RESPONSE);
    }

    knoxToken = KnoxToken.fromDTResponse(response.getRight(), response.getLeft());
    monitorKnoxToken();
    getAccessTokenProvider().updateDelegationToken(knoxToken);

    // Print a small bit of the secret and the expiration
    LOG.info("Bonded to Knox token {}, expires {}",
             knoxToken.getPrintableAccessToken(),
             (UTCClock.secondsToDateTime(knoxToken.getExpiry()).map(OffsetDateTime::toString).orElse("undefined")));

    if (knoxToken.getEndpointPublicCert() != null) {
      LOG.debug("Including public cert in the delegation token.");
    }
  }

  private Pair<RequestDTResponseMessage, String> requestDelegationToken() throws IOException {
    Pair<KnoxSession, String> sessionDetails = getDTSession();

    KnoxSession session = sessionDetails.getLeft();
    String origin = sessionDetails.getRight();

    try {
      return Pair.of(getClient().requestKnoxDelegationToken(session, origin, getCanonicalUri()), origin);
    } finally {
      IOUtils.cleanupWithLogger(LOG, session);
    }
  }

  private GoogleTempCredentials collectGCPCredentials() throws IOException {
    if (needsGCPCredentials()) {
      marshalledCredentials = updateGCPCredentials();
    }
    return marshalledCredentials;
  }

  synchronized GoogleTempCredentials updateGCPCredentials() throws IOException {
    CloudAccessBrokerSession session = getClient().createKnoxCABSession(knoxToken);

    try {
      return new GoogleTempCredentials(getClient().fetchCloudCredentials(session));
    } finally {
      IOUtils.cleanupWithLogger(LOG, session);
    }
  }

  private boolean needsGCPCredentials() {
    boolean isNeeded = true;

    if (marshalledCredentials != null && !marshalledCredentials.isEmpty()) {
      long expiration = marshalledCredentials.getExpiration();
      if (expiration > 0 && hasExpired(expiration)) {
        LOG.debug("Expiring current GCP credentials");
        resetGCPCredentials();
      } else {
        LOG.debug("Current GCP credentials are still valid");
        isNeeded = false;
      }
    } else {
      LOG.debug("No marshalled GCP credentials");
    }

    return isNeeded;
  }

  private void resetGCPCredentials() {
    marshalledCredentials = null;
  }

  private Pair<KnoxSession, String> getDTSession() throws IOException {
    IDBClient<AccessTokenProvider.AccessToken> client = getClient();

    LOG.debug("Attempting to create a Knox delegation token session using local credentials (kerberos, simple)");
    Pair<KnoxSession, String> sessionDetails = client.createKnoxDTSession(getConf());
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

  private Text getOwnerText(UserGroupInformation owner) {
    return new Text(owner.getUserName());
  }

  private URI getCanonicalUri() {
    return this.getFileSystem().getUri();
  }

  private void monitorKnoxToken() {
    // Maybe initialize the Knox token monitor
    initKnoxTokenMonitor();

    // Only start monitoring the token if the token monitor has been initialized
    if (knoxTokenMonitor != null) {
      long knoxTokenExpirationOffset = getConf().getLong(IDBROKER_DT_EXPIRATION_OFFSET.getPropertyName(),
          Long.parseLong(IDBROKER_DT_EXPIRATION_OFFSET.getDefaultValue()));

      knoxTokenMonitor.monitorKnoxToken(knoxToken, knoxTokenExpirationOffset, new GetKnoxTokenCommand());
    }
  }

  private class GetKnoxTokenCommand implements KnoxTokenMonitor.GetKnoxTokenCommand {
    @Override
    public void execute(KnoxToken knoxToken) throws IOException {
      lock.lock();
      try {
        getNewKnoxToken();
      } finally {
        lock.unlock();
      }
    }
  }
}

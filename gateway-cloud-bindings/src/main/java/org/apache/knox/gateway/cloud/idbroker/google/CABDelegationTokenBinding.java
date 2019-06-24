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

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_DT_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_DT_EXPIRATION_OFFSET;

import com.google.cloud.hadoop.fs.gcs.auth.AbstractDelegationTokenBinding;
import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import com.google.cloud.hadoop.util.AccessTokenProvider;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.TimeUnit;

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


  private IDBClient<AccessTokenProvider.AccessToken> cabClient;

  /**
   * This is the knox token.
   */
  private KnoxToken knoxToken = null;

  private final KnoxTokenMonitor knoxTokenMonitor;

  private GoogleTempCredentials marshalledCredentials = null;

  private AccessTokenProvider accessTokenProvider;

  public CABDelegationTokenBinding() {
    super(CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND);

    knoxTokenMonitor = new KnoxTokenMonitor();
  }

  IDBClient<AccessTokenProvider.AccessToken> getClient() {
    if (cabClient == null) {
      try {
        cabClient = CABUtils.newClient(getConf(), UserGroupInformation.getCurrentUser());
      } catch (IOException e) {
        LOG.error(e.getMessage());
      }
    }
    return cabClient;
  }

  Configuration getConf() {
    return getFileSystem().getConf();
  }


  /**
   * Return the unbonded credentials.
   *
   * @throws IOException failure
   */
  public AccessTokenProvider deployUnbonded()
      throws IOException {
    // then ask for a token
    maybeRenewAccessToken();

    return getAccessTokenProvider();
  }

  AccessTokenProvider getAccessTokenProvider() {
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
      accessTokenProvider =
          new CloudAccessBrokerTokenProvider(cabClient, knoxToken, gcpToken, gcpTokenExp);
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
  public DelegationTokenIdentifier createTokenIdentifier() throws IOException {
    DelegationTokenIdentifier identifier;

    long expiryTime;
    String knoxDT;
    String tokenType = null;
    String targetURL = CABUtils.getCloudAccessBrokerURL(getConf(), cabClient.getGatewayAddress());
    String endpointCertificate;

    maybeRenewAccessToken();

    knoxDT = knoxToken.getAccessToken();
    expiryTime = knoxToken.getExpiry();
    endpointCertificate = knoxToken.getEndpointPublicCert();

    GoogleTempCredentials gcpCredentials;
    if (getConf().getBoolean(CloudAccessBrokerBindingConstants.CONFIG_INIT_CLOUD_CREDS, true)) {
      gcpCredentials = collectGCPCredentials();
    } else {
      gcpCredentials = new GoogleTempCredentials();
    }

    // build the identifier
    identifier =
        new CABGCPTokenIdentifier(getKind(),
                                  getOwnerText(UserGroupInformation.getCurrentUser()),
                                  getCanonicalUri(),
                                  knoxDT,
                                  expiryTime,
                                  tokenType,
                                  targetURL,
                                  endpointCertificate,
                                  gcpCredentials,
                                  "Created from " + cabClient.getGatewayAddress());

    LOG.debug("Created delegation token identifier {}", identifier);

    return identifier;
  }

  @Override
  public DelegationTokenIdentifier createTokenIdentifier(Text renewer) throws IOException {
    // Ignore renewer for now...
    return createTokenIdentifier();
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
    if ((knoxToken == null) || knoxToken.isExpired()) {
      LOG.info(knoxToken == null ?
          "Requesting initial delegation token" :
          "Current delegation token has expired: requesting a new one");
      bondToRequestedToken(requestDelegationToken());
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
    CABGCPTokenIdentifier tokenIdentifier =
        convertTokenIdentifier(retrievedIdentifier, CABGCPTokenIdentifier.class);

    String endpointCert = tokenIdentifier.getCertificate();
    if (endpointCert != null) {
      LOG.debug("Using Cloud Access Broker public cert from delegation token");
    }

    knoxToken = new KnoxToken("origin", tokenIdentifier.getAccessToken(), tokenIdentifier.getTokenType(), tokenIdentifier.getExpiryTime(), endpointCert);

    startKnoxTokenMonitor();

    // GCP credentials
    marshalledCredentials = tokenIdentifier.getMarshalledCredentials();
    LOG.debug("Marshalled GCP credentials: " + marshalledCredentials.toString());

    return getAccessTokenProvider();
  }

  /**
   * Bond to the response of a knox login + DT request.
   * This doesn't kick off the first retrieval of secrets.
   *
   * @param response response from the DT request.
   * @throws IOException failure to get an GCP credential session
   */
  private void bondToRequestedToken(final Pair<RequestDTResponseMessage, String> response)
      throws IOException {
    if ((response == null) || (response.getLeft() == null)) {
      throw new DelegationTokenIOException(E_INVALID_DT_RESPONSE);
    }

    knoxToken = KnoxToken.fromDTResponse(response.getRight(), response.getLeft());

    startKnoxTokenMonitor();

    // Print a small bit of the secret and the expiration
    LOG.info("Bonded to Knox token {}, expires {}",
        knoxToken.getAccessToken().substring(0, 10),
        (UTCClock.secondsToDateTime(knoxToken.getExpiry())));

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

  private synchronized GoogleTempCredentials collectGCPCredentials() throws IOException {
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

  private synchronized boolean needsGCPCredentials() {
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

  private synchronized void resetGCPCredentials() {
    marshalledCredentials = null;
  }

  private Pair<KnoxSession, String> getDTSession() throws IOException {
    IDBClient<AccessTokenProvider.AccessToken> client = getClient();

    LOG.debug("Attempting to create a Knox delegation token session using local credentials (kerberos, simple)");
    Pair<KnoxSession, String> sessionDetails = client.createKnoxDTSession(getConf());

    if (sessionDetails.getLeft() == null) {
      LOG.debug("Local credentials are not available, attempting to create a Knox delegation token session using an existing Knox delegation token");
      // Kerberos or simple authentication is not available. Attempt to create a session to the
      // CAB-specific topology using the KnoxToken as the credential...
      if (knoxToken != null) {
        if (knoxToken.isExpired()) {
          LOG.debug("The Delegation token is expired, failing to create a Knox delegation token session.");
        } else {
          LOG.debug("Get a new Knox session from Delegation token");
          // If we are using a Knox delegation token, we need to use the CAB-specific endpoint rather
          // than the DT-specific endpoint since the CAB-specific endpoint has the ability to authenticate
          // users using a Knox delegation token and the DT-specific endpoint requires Kerberos.
          sessionDetails = Pair.of(client.createKnoxCABSession(knoxToken), "delegation token");
        }
      }
      else {
        LOG.debug("The Delegation token is not available, failing to create a Knox delegation token session.");
      }

      if (LOG.isDebugEnabled()) {
        if (sessionDetails.getLeft() == null) {
          LOG.debug("Failed to created a Knox delegation token session using either local credentials (kerberos, simple) or an existing Knox delegation token");
        } else {
          LOG.debug("Created a Knox delegation token session using an existing Knox delegation token");
        }
      }
    } else {
      LOG.debug("Created a Knox delegation token session using local credentials (kerberos, simple)");
    }

    return sessionDetails;
  }

  private Text getOwnerText(UserGroupInformation owner) {
    return new Text(owner.getUserName());
  }

  private URI getCanonicalUri() {
    return this.getFileSystem().getUri();
  }

  private void startKnoxTokenMonitor() {
    long knoxTokenExpirationOffset = getConf().getLong(IDBROKER_DT_EXPIRATION_OFFSET.getPropertyName(),
        Long.valueOf(IDBROKER_DT_EXPIRATION_OFFSET.getDefaultValue()));

    knoxTokenMonitor.monitorKnoxToken(knoxToken, knoxTokenExpirationOffset, new GetKnoxTokenCommand());
  }

  private class GetKnoxTokenCommand implements KnoxTokenMonitor.GetKnoxTokenCommand {
    @Override
    public void execute(KnoxToken knoxToken) throws IOException {
      bondToRequestedToken(requestDelegationToken());
    }
  }
}

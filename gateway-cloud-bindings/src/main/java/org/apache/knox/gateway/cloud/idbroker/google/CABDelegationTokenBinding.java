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

import com.google.cloud.hadoop.fs.gcs.auth.AbstractDelegationTokenBinding;
import com.google.cloud.hadoop.fs.gcs.auth.AbstractGCPTokenIdentifier;
import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.KnoxSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.*;

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


  /**
   * This is a connection to the knox DT issuing endpoint.
   * it is non-empty if this binding was instantiated without
   * a delegation token, that is: new DTs can be requested.
   * Will be set in {@link #deployUnbonded()}.
   */
  private Optional<KnoxSession> loginSession = Optional.empty();

  /**
   * This is the knox token.
   */
  private String accessToken = null;

  private String accessTokenType = null;

  private String accessTokenTargetURL = null;

  /**
   * Expiry time for the DT.
   */
  private long accessTokenExpiresSeconds;

  private String gatewayCertificate = null;


  /**
   * The session to the GCP credential issuing endpoint.
   */
  private Optional<KnoxSession> gcpCredentialSession = Optional.empty();

  private GoogleTempCredentials marshalledCredentials = null;

  /**
   * The token identifier bound to in
   * {@link #bindToTokenIdentifier(AbstractGCPTokenIdentifier)}.
   */
  private Optional<AbstractGCPTokenIdentifier> boundTokenIdentifier
      = Optional.empty();

  private AccessTokenProvider accessTokenProvider;

  public CABDelegationTokenBinding() {
    super(CloudAccessBrokerBindingConstants.CAB_TOKEN_KIND);
  }

  private Configuration getConf() {
    return getFileSystem().getConf();
  }

  /**
   * Create a delegation token for the user.
   * This will only be called if a new DT is needed, that is: the
   * filesystem has been deployed unbonded.
   * @return the token
   * @throws IOException if one cannot be created
   */
  public org.apache.hadoop.security.token.Token<AbstractGCPTokenIdentifier> createDelegationToken() throws IOException {
    AbstractGCPTokenIdentifier tokenIdentifier = requireNonNull(createTokenIdentifier(), "Token identifier");

    org.apache.hadoop.security.token.Token<AbstractGCPTokenIdentifier> token =
        new org.apache.hadoop.security.token.Token<>(tokenIdentifier, secretManager);
    token.setKind(getKind());
    LOG.debug("Created delegation token {} with identifier {}",
              token,
              tokenIdentifier);
    return token;
  }


  /**
   * Return the unbonded credentials.
   * @throws IOException failure
   */
  public AccessTokenProvider deployUnbonded()
      throws IOException {
    // set the expiry time to zero
    accessTokenExpiresSeconds = 0;

    // then ask for a token
    maybeRenewAccessToken();

    return getAccessTokenProvider();
  }

  private AccessTokenProvider getAccessTokenProvider() {
    if (accessTokenProvider == null) {
      LOG.debug("No existing accessTokenProvider");
      String gcpToken  = null;
      long gcpTokenExp = -1;

      if (marshalledCredentials != null) {
        LOG.debug("Using existing marshalled credentials");
        gcpToken = marshalledCredentials.getToken();
        gcpTokenExp = marshalledCredentials.getExpiration();
      }

      LOG.debug("Creating new accessTokenProvider");
      accessTokenProvider =
          new CloudAccessBrokerTokenProvider(accessToken,
                                             accessTokenType,
                                             accessTokenTargetURL,
                                             gcpToken,
                                             gcpTokenExp,
                                             gatewayCertificate);
    }
    LOG.debug("Created new accessTokenProvider");
    return accessTokenProvider;
  }

  /**
   * Create a Cloud Access Broker token, possibly including an initial set of GCP credentials.
   *
   * @return the token identifier for the DT
   *
   * @throws IOException failure to collect a DT.
   */
  @Override
  public AbstractGCPTokenIdentifier createTokenIdentifier() throws IOException {
    AbstractGCPTokenIdentifier identifier = null;

    long expiryTime;
    String knoxDT;
    String tokenType = null;
    String targetURL = CABUtils.getCloudAccessBrokerURL(getConf());
    String endpointCertificate = null;


    if (maybeRenewAccessToken()) {
      // If the delegation token has been refreshed, refreshed the cached parts.
      knoxDT = accessToken;
      expiryTime = accessTokenExpiresSeconds;
      if (accessTokenType != null) {
        tokenType = accessTokenType;
      }
      if (accessTokenTargetURL != null) {
        targetURL = accessTokenTargetURL;
      }

      if (gatewayCertificate != null) {
        endpointCertificate = gatewayCertificate;
      }
    } else {
      // request a new DT so that it is valid
      RequestDTResponseMessage dtResponse = requestDelegationToken();
      knoxDT = dtResponse.access_token;
      expiryTime = dtResponse.expiryTimeSeconds();
      tokenType = dtResponse.token_type;
      if (StringUtils.isNotEmpty(dtResponse.target_url)) {
        targetURL = dtResponse.target_url;
      }
      endpointCertificate = dtResponse.endpoint_public_cert;
    }

    GoogleTempCredentials gcpCredentials = null;
    if (getConf().getBoolean("fs.gs.ext.cab.init.credentials", true)) {
      gcpCredentials = collectGCPCredentials();
    } else {
      gcpCredentials = new GoogleTempCredentials();
    }

    // build the identifier
    identifier =
        new CABGCPTokenIdentifier(getKind(),
                                  getOwnerText(),
                                  getCanonicalUri(),
                                  knoxDT,
                                  expiryTime,
                                  tokenType,
                                  targetURL,
                                  endpointCertificate,
                                  gcpCredentials,
                                  "Created from " + CABUtils.getCloudAccessBrokerAddress(getConf()));

    LOG.debug("Created delegation token identifier {}", identifier);

    return identifier;
  }

  @Override
  public AbstractGCPTokenIdentifier createTokenIdentifier(Text renewer) throws IOException {
    // Ignore renewer for now...
    return createTokenIdentifier();
  }

  @Override
  public AbstractGCPTokenIdentifier createEmptyIdentifier() {
    return null;
  }

  /**
   * If a new access token needed, collect one.
   * This does not guarantee that one can be requested, only that
   * the current token has expired.
   * @return true iff a new access token was requested.
   */
  private boolean maybeRenewAccessToken() throws IOException {
    if (hasExpired(accessTokenExpiresSeconds)) {
      LOG.debug(accessTokenExpiresSeconds == 0 ?
          "Requesting initial delegation token" :
          "Current delegation token has expired: requesting a new one");
      bondToRequestedToken(requestDelegationToken());
      return true;
    } else {
      return false;
    }
  }

  /**
   * Has a time expired?
   * @param seconds expiry time.
   * @return true if the token is expired relative to the clock.
   */
  boolean hasExpired(long seconds) {
    return (seconds < TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()));
  }


  @Override
  public AccessTokenProvider bindToTokenIdentifier(AbstractGCPTokenIdentifier retrievedIdentifier)
      throws IOException {
    CABGCPTokenIdentifier tokenIdentifier =
        convertTokenIdentifier(retrievedIdentifier, CABGCPTokenIdentifier.class);
    boundTokenIdentifier = Optional.of(tokenIdentifier);
    accessToken = tokenIdentifier.getAccessToken();
    accessTokenExpiresSeconds = tokenIdentifier.getExpiryTime();
    accessTokenType = tokenIdentifier.getTokenType();
    accessTokenTargetURL = tokenIdentifier.getTargetURL();

    String endpointCert = tokenIdentifier.getCertificate();
    if (endpointCert != null) {
      gatewayCertificate = endpointCert;
      LOG.debug("Using Cloud Access Broker public cert from delegation token");
    }

    // GCP credentials
    marshalledCredentials = tokenIdentifier.getMarshalledCredentials();
    LOG.debug("Marshalled GCP credentials: " + marshalledCredentials.toString());

    try {
      LOG.debug("Creating Cloud Access Broker client session");
      gcpCredentialSession =
          Optional.of(CABUtils.getCloudSession(CABUtils.getCloudAccessBrokerURL(getConf()),
                                               accessToken,
                                               accessTokenType,
                                               gatewayCertificate));
    } catch (Exception e) {
      LOG.debug("Error creating Cloud Access Broker client session", e);
      throw new DelegationTokenIOException(E_FAILED_CLOUD_SESSION, e);
    }

    return getAccessTokenProvider();
  }

  /**
   * Bond to the response of a knox login + DT request.
   * This doesn't kick off the first retrieval of secrets.
   *
   * @param response response from the DT request.
   *
   * @throws IOException failure to get an GCP credential session
   */
  public void bondToRequestedToken(final RequestDTResponseMessage response)
      throws IOException {
    if (response == null) {
      throw new DelegationTokenIOException(E_INVALID_DT_RESPONSE);
    }

    final String token = response.access_token;
    // print a small bit of the secret
    LOG.debug("Bonded to Knox delegation token {}", token.substring(0, 10));
    accessToken = token;
    accessTokenExpiresSeconds = response.expiryTimeSeconds();
    accessTokenType = response.token_type;
    if (response.target_url != null) {
      accessTokenTargetURL = response.target_url;
    }

    if (response.endpoint_public_cert != null) {
      gatewayCertificate = response.endpoint_public_cert;
      LOG.debug("Applying public cert from delegation token.");
    }

    try {
      gcpCredentialSession = Optional.of(CABUtils.getCloudSession(CABUtils.getCloudAccessBrokerURL(getConf()),
                                         accessToken,
                                         accessTokenType,
                                         gatewayCertificate));
    } catch (URISyntaxException | IllegalArgumentException e) {
      throw new DelegationTokenIOException(E_FAILED_DT_SESSION, e);
    }
  }

  private RequestDTResponseMessage requestDelegationToken() throws IOException {
    return CABUtils.requestDelegationToken(getConf(), getDTSession());
  }

  private synchronized GoogleTempCredentials collectGCPCredentials() throws IOException {
    if (needsGCPCredentials()) {
      updateGCPCredentials();
    }
    return marshalledCredentials;
  }

  private synchronized void updateGCPCredentials() throws IOException {
    marshalledCredentials =
        new GoogleTempCredentials(CABUtils.getCloudCredentials(getConf(),
            gcpCredentialSession.orElseThrow(
                () -> new DelegationTokenIOException(E_NO_SESSION_TO_KNOX_CREDS))));
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

  private KnoxSession getDTSession() {
    if (!loginSession.isPresent()) {
      loginSession = Optional.of(CABUtils.createDTSession(getConf(), gatewayCertificate));
    }
    return loginSession.get();
  }

}

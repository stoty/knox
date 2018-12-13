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
import org.apache.hadoop.util.JsonSerialization;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.HadoopException;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.knox.token.Get;
import org.apache.knox.gateway.shell.knox.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;
import static org.apache.knox.gateway.cloud.idbroker.google.CABUtils.getRequiredConfigSecret;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.*;

public class CABDelegationTokenBinding extends AbstractDelegationTokenBinding {

  protected static final Logger LOG =
      LoggerFactory.getLogger(CABDelegationTokenBinding.class);

  static final String E_MISSING_DT_ADDRESS =
      "Missing Cloud Access Broker delegation token address configuration" 
          + " in " + CONFIG_CAB_DT_PATH;

  static final String E_INVALID_DT_RESPONSE =
      "Invalid delegation token response";

  static final String E_FAILED_DT_ACQUISITION =
      "Error acquiring delegation token";

  static final String E_FAILED_DT_SESSION =
      "Error establishing session with delegation token provider";

  static final String E_FAILED_CLOUD_SESSION =
      "Error establishing session with Cloud Access Broker credential provider";

  static final String E_NO_SESSION_TO_KNOX_CREDS
      = "No session with Knox credential endpoint";

  static final String E_MISSING_DT_USERNAME_CONFIG =
      "Missing Cloud Access Broker delegation token username configuration" 
          + " in " + CONFIG_DT_USERNAME;

  static final String E_MISSING_DT_PASS_CONFIG =
      "Missing Cloud Access Broker delegation token password configuration" 
          + " in " + CONFIG_DT_PASS;

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
      accessTokenProvider =
          new CloudAccessBrokerTokenProvider(accessToken,
                                             accessTokenType,
                                             accessTokenTargetURL);
    }
    return accessTokenProvider;
  }

  /**
   * The heavy lifting: collect an IDB token.
   * Maybe also: collect some AWS Credentials.
   * @return the token identifier for the DT
   * @throws IOException failure to collect a DT.
   */
  @Override
  public AbstractGCPTokenIdentifier createTokenIdentifier() throws IOException {
    AbstractGCPTokenIdentifier identifier = null;

    long expiryTime;
    String knoxDT;
    String tokenType = null;
    String targetURL = CABUtils.getCloudAccessBrokerURL(getConf());

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
    } else {
      // request a new DT so that it is valid
      RequestDTResponseMessage dtResponse = requestDelegationToken();
      knoxDT = dtResponse.access_token;
      expiryTime = dtResponse.expiryTimeSeconds();
      tokenType = dtResponse.token_type;
      if (StringUtils.isNotEmpty(dtResponse.target_url)) {
        targetURL = dtResponse.target_url;
      }
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
                                  collectGCPCredentials(),
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

    // GCP credentials
    marshalledCredentials = tokenIdentifier.getMarshalledCredentials();
    try {
      gcpCredentialSession =
          Optional.of(CABUtils.getCloudSession(getConf(),
                                               accessToken,
                                               accessTokenType));
    } catch (Exception e) {
      throw new DelegationTokenIOException(E_FAILED_CLOUD_SESSION, e);
    }

    return getAccessTokenProvider();
  }

  /**
   * Bond to the response of a knox login + DT request.
   * This doesn't kick off the first retrieval of secrets.
   * @param response response from the DT request.
   * @throws IOException failure to get an AWS credential session
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

    try {
      gcpCredentialSession = Optional.of(CABUtils.getCloudSession(getConf(),
                                         response.access_token,
                                         response.token_type));
    } catch (URISyntaxException | IllegalArgumentException e) {
      throw new DelegationTokenIOException(E_FAILED_DT_SESSION, e);
    }
  }

  private RequestDTResponseMessage requestDelegationToken() throws IOException {
    RequestDTResponseMessage delegationTokenResponse = null;

    try {
      String gateway = CABUtils.getCloudAccessBrokerAddress(getConf());
      Get.Request request = Token.get(getDTSession());
      try {
        delegationTokenResponse = processGet(RequestDTResponseMessage.class,
            gateway,
            request.getRequestURI(),
            request.now());
        if (StringUtils.isEmpty(delegationTokenResponse.access_token)) {
          throw new DelegationTokenIOException("No access token from DT login");
        }
      } catch (HadoopException e) {
        // add the URL
        throw new DelegationTokenIOException("From " + gateway + " : " + e.toString(), e);
      }
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      LOG.error(E_FAILED_DT_ACQUISITION, e);
      throw new DelegationTokenIOException(E_FAILED_DT_ACQUISITION
          + ": " + e, e);
    }

    return delegationTokenResponse;
  }

  /**
   * handle a GET response by validating headers and status,
   * parsing to the given type.
   * @param <T> final type
   * @param clazz class of final type
   * @param requestURI URI of the request
   * @param response GET response
   * @return an instant of the JSON-unmarshalled type
   * @throws IOException failure
   */
  public <T> T processGet(final Class<T> clazz,
                          final String gateway,
                          final URI requestURI,
                          final BasicResponse response) throws IOException {

    int statusCode = response.getStatusCode();
    String type = response.getContentType();

    String dest = requestURI != null? requestURI.toString() :
        ("path under " + gateway);
    if (statusCode != 200) {
      String body = response.getString();
      LOG.error("Bad response {} content-type {}\n{}", statusCode, type, body);
      throw new DelegationTokenIOException(String.format("Wrong status code %s from session auth to %s: %s",
                                                         statusCode,
                                                         dest,
                                                         body));
    }

    // Fail if there is no data
    if (response.getContentLength() <= 0) {
      throw new DelegationTokenIOException(String.format("No content in response from %s; content-type %s",
                                                         dest,
                                                         type));
    }

    if (!IDBConstants.MIME_TYPE_JSON.equals(type)) {
      String body = response.getString();
      LOG.error("Bad response {} content-type {}\n{}", statusCode, type, body);
      throw new DelegationTokenIOException(String.format("Wrong status code %s from session auth to %s: %s",
                                                         statusCode,
                                                         dest,
                                                         body));
    }

    JsonSerialization<T> serDeser = new JsonSerialization<>(clazz,
        false, true);
    InputStream stream = response.getStream();
    return serDeser.fromJsonStream(stream);
  }

  private synchronized GoogleTempCredentials collectGCPCredentials() throws IOException {
    if (needsGCPCredentials()) {
      updateGCPCredentials();
    }
    return  marshalledCredentials;
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
        LOG.info("Expiring current GCP credentials");
        resetGCPCredentials();
      } else {
        isNeeded = false;
      }
    }

    return isNeeded;
  }

  private synchronized void resetGCPCredentials() {
    marshalledCredentials = null;
  }

  private KnoxSession getDTSession() {
    if (!loginSession.isPresent()) {
      loginSession = Optional.of(createDTSession());
    }
    return loginSession.get();
  }

  /**
   * Create the DT session
   * @return the session
   * @throws IllegalStateException bad state
   */
  private KnoxSession createDTSession() throws IllegalStateException {
    String dtAddress = CABUtils.getDelegationTokenProviderURL(getConf());
    if (dtAddress == null) {
      throw new IllegalStateException(E_MISSING_DT_ADDRESS);
    }

    // Check for an alias first (falling back to clear-text in config)
    String dtUsername = getRequiredConfigSecret(getConf(),
        CONFIG_DT_USERNAME,
        DT_USERNAME_ENV_VAR,
        E_MISSING_DT_USERNAME_CONFIG);

    // Check for an alias first (falling back to clear-text in config)
    String dtPass = getRequiredConfigSecret(getConf(), 
        CONFIG_DT_PASS,
        DT_PASS_ENV_VAR,
        E_MISSING_DT_PASS_CONFIG);

    KnoxSession dtSession = null;

    try {
      dtSession = KnoxSession.login(dtAddress, dtUsername, dtPass,
          CABUtils.getTrustStoreLocation(getConf()),
          getTrustStorePass(getConf()));
    } catch (URISyntaxException e) {
      LOG.error(E_FAILED_DT_SESSION, e);
      throw new IllegalStateException(E_FAILED_DT_SESSION, e);
    }

    return dtSession;
  }

  /**
   * Get the password for the trust store.
   * This code is inconsistent with the one in CABUtils; they need 
   * to be resolved. For now, leaving them separate.
   * @param conf config
   * @return trust store password, or null
   */
  private static String getTrustStorePass(final Configuration conf) {
    String result;
    // First, consult the configuration for an overriding alias name
    String alias = conf.get(CONFIG_CAB_TRUST_STORE_PASS,
                                 CONFIG_CAB_TRUST_STORE_PASS);

    // Then, lookup the secret for the alias
    // Check for an alias first (falling back to clear-text in config)
    result = CABUtils.getConfigSecret(conf, alias,
        CONFIG_CAB_TRUST_STORE_PASS_ENV_VAR);

    return result;
  }

}

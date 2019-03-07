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

import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.KnoxSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;


public class CloudAccessBrokerTokenProvider implements AccessTokenProvider {

  private static final Logger LOG = LoggerFactory.getLogger(CloudAccessBrokerTokenProvider.class);

  private static final String E_MISSING_DT =
      "Missing required delegation token.";

  private static final String E_MISSING_CAB_ADDR_CONFIG =
      "Missing Cloud Access Broker address configuration.";

  private static final String DEFAULT_TOKEN_TYPE = "Bearer";

  private Configuration config = null;

  // The GCP access token
  private AccessToken accessToken = null;

  // The amount by which the access token expiration time will be adjusted for evaluation to trigger updating of those
  // access tokens which will be expiring soon.
  private static final Long accessTokenExpirationThreshold = 30000L;

  // Session for interacting with the DT service
  private KnoxSession dtSession = null;

  // DT details for use in requesting cloud credentials from the CAB
  private String delegationTokenType = null;
  private String delegationTokenTarget = null;
  private String delegationToken = null;

  // The  CABpublic cert
  private String cloudAccessBrokerCertificate = null;

  // Session for interacting with CAB for requesting GCP credentials
  private KnoxSession credentialSession = null;


  public CloudAccessBrokerTokenProvider() {
  }

  public CloudAccessBrokerTokenProvider(String delegationToken,
                                        String delegationTokenType,
                                        String delegationTokenTarget) {
    this.delegationTokenType = delegationTokenType;
    this.delegationTokenTarget = delegationTokenTarget;
    this.delegationToken = delegationToken;
  }

  public CloudAccessBrokerTokenProvider(String delegationToken,
                                        String delegationTokenType,
                                        String delegationTokenTarget,
                                        String accessToken,
                                        long   accessTokenExpiration) {
    this(delegationToken, delegationTokenType, delegationTokenTarget);

    if (accessToken != null) {
      this.accessToken =
          new AccessTokenProvider.AccessToken(accessToken, accessTokenExpiration);
    }
  }

  public CloudAccessBrokerTokenProvider(String delegationToken,
                                        String delegationTokenType,
                                        String delegationTokenTarget,
                                        String accessToken,
                                        long   accessTokenExpiration,
                                        String cabCertificate) {
    this(delegationToken, delegationTokenType, delegationTokenTarget, accessToken, accessTokenExpiration);
    cloudAccessBrokerCertificate = cabCertificate;
  }

  @Override
  public void setConf(Configuration configuration) {
    this.config = configuration;
  }

  @Override
  public Configuration getConf() {
    return config;
  }

  @Override
  public AccessToken getAccessToken() {
    if (!isValid(accessToken)) {
      LOG.debug("No existing valid access token...attempting to fetch new one");
      try {
        accessToken = fetchAccessToken();
      } catch (IOException e) {
        LOG.debug("Failed to fetch new access token: " + e.getMessage());
        // wrap, again.
        throw new RuntimeException(e);
      }
    } else {
      LOG.debug("Using existing GCP access token");
    }
    return accessToken;
  }

  @Override
  public void refresh() throws IOException {
    accessToken = fetchAccessToken();
  }

  /**
   * Determine whether the specified access token needs to be updated, based on its expiration time.
   *
   * @param accessToken The AccessToken to evaluate.
   *
   * @return true, if the token has expired, or will be expiring soon; otherwise, false.
   */
  private boolean isValid(AccessToken accessToken) {
    return (accessToken != null) && (accessToken.getExpirationTimeMilliSeconds() >= System.currentTimeMillis() + accessTokenExpirationThreshold);
  }


  /**
   * Request a GCP access token from the CAB.
   *
   * @return An AccessToken, or null.
   *
   * @throws IOException
   */
  private AccessToken fetchAccessToken() throws IOException {
    AccessToken result = null;

    // Use the previously-established delegation token for interacting with the
    // CAB
    if (delegationToken == null || delegationToken.isEmpty()) {
      throw new IllegalArgumentException(E_MISSING_DT);
    }

    String accessBrokerAddress = delegationTokenTarget;

    // Treat the configured CAB address as a fallback for the DT-specified
    // address
    if (accessBrokerAddress == null || accessBrokerAddress.isEmpty()) {
      String configuredCABAddress = CABUtils.getCloudAccessBrokerURL(config);
      if (configuredCABAddress != null) {
        accessBrokerAddress = configuredCABAddress;
      }
    }

    // There must be a CAB address
    if (accessBrokerAddress == null) {
      throw new IllegalStateException(E_MISSING_CAB_ADDR_CONFIG);
    }

    KnoxSession session = null;
    try {
      session = getCredentialSession(accessBrokerAddress);

      // Get the cloud credentials from the CAB
      try {
        result = CABUtils.getCloudCredentials(config, session);
      } catch (IOException e) {
        // Check for exception message containing "400 Bad request: token has expired"
        if (e.getMessage().contains("token has expired")) {
          LOG.info("Delegation token has expired.");

          // Refresh the delegation token
          refreshDT();

          // Attempt the credentials acquisition again
          result = CABUtils.getCloudCredentials(config,
                                                getCredentialSession(accessBrokerAddress, true));
        } else {
          LOG.debug("Error requesting cloud credentials: " + e.getMessage());
          throw e; // If it's not a token error, just pass it along
        }
      }
      if (result != null) {
        LOG.debug("Acquired cloud credentials: token={}, expires={}",
                  result.getToken().substring(0, 8),
                  new Date(result.getExpirationTimeMilliSeconds()));
      }
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      LOG.error(e.getMessage());
      LOG.debug("Failed to get access token.", e);
      throw new DelegationTokenIOException(e.getMessage(), e);
    } finally {
      try {
        if (session != null) {
          session.shutdown();
        }
      } catch (Exception e) {
        LOG.warn(e.getMessage());
      }
    }

    return result;
  }

  private String getDelegationTokenType() {
    return (delegationTokenType != null ? delegationTokenType : DEFAULT_TOKEN_TYPE);
  }

  private KnoxSession getDTSession() {
    if (dtSession == null) {
      dtSession = CABUtils.createDTSession(config, cloudAccessBrokerCertificate);
    }
    return dtSession;
  }

  /**
   * Refresh the delegation token used for interactions with the CAB.
   *
   * @throws IOException
   */
  private void refreshDT() throws IOException {
    LOG.debug("Refreshing delegation token");

    // Request the new DT
    RequestDTResponseMessage response = CABUtils.requestDelegationToken(config, getDTSession());

    // Update the DT details so subsequent credentials requests will use them
    delegationToken = response.access_token;
    delegationTokenType = response.token_type;
    delegationTokenTarget = response.target_url;
  }

  private KnoxSession getCredentialSession(String accessBrokerAddress) throws Exception {
    return getCredentialSession(accessBrokerAddress, false);
  }

  /**
   *
   * @param accessBrokerAddress The address of the CAB
   * @param refresh If true, force the creation of a new session; otherwise, re-use the session if it exists
   *
   * @return The KnoxSession or null.
   *
   * @throws Exception
   */
  private KnoxSession getCredentialSession(String accessBrokerAddress, boolean refresh) throws Exception {
    if (credentialSession == null || refresh) {
      LOG.debug("Creating new Cloud Access Broker credential session");

      // Define the session for interacting with the CAB
      if (cloudAccessBrokerCertificate != null && !cloudAccessBrokerCertificate.isEmpty()) {
        LOG.debug("Establishing Cloud Access Broker client session with public cert from delegation token.");
        credentialSession =
            CABUtils.getCloudSession(accessBrokerAddress,
                delegationToken,
                getDelegationTokenType(),
                cloudAccessBrokerCertificate);
      } else {
        credentialSession =
            CABUtils.getCloudSession(accessBrokerAddress,
                delegationToken,
                getDelegationTokenType(),
                CABUtils.getTrustStoreLocation(config),
                CABUtils.getTrustStorePass(config));
      }
    }

    return credentialSession;
  }

}

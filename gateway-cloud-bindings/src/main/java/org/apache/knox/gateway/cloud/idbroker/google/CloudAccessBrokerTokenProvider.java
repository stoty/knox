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
import org.apache.knox.gateway.shell.KnoxSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;


public class CloudAccessBrokerTokenProvider implements AccessTokenProvider {

  private static final Logger LOG = LoggerFactory.getLogger(CloudAccessBrokerTokenProvider.class);

  private static final String E_MISSING_DT =
      "Missing required delegation token.";

  private static final String E_MISSING_CAB_ADDR_CONFIG =
      "Missing Cloud Access Broker address configuration.";

  private static final String DEFAULT_TOKEN_TYPE = "Bearer";

  private Configuration config = null;

  private AccessToken accessToken = null;

  // The amount by which the access token expiration time will be adjusted for evaluation to trigger updating of those
  // access tokens which will be expiring soon.
  private static final Long accessTokenExpirationThreshold = 30000L;

  private String delegationTokenType = null;
  private String delegationTokenTarget = null;
  private String delegationToken = null;

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
    if (isValid(accessToken)) {
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

  /**
   * Determine whether the specified access token needs to be updated, based on its expiration time.
   *
   * @param accessToken The AccessToken to evaluate.
   *
   * @return true, if the token has expired, or will be expiring soon; otherwise, false.
   */
  private boolean isValid(AccessToken accessToken) {
    return (accessToken != null) && (accessToken.getExpirationTimeMilliSeconds() <= System.currentTimeMillis() + accessTokenExpirationThreshold);
  }

  @Override
  public void refresh() throws IOException {
    accessToken = fetchAccessToken();
  }

  private AccessToken fetchAccessToken() throws IOException {
    AccessToken result = null;

    // Use the previously-established delegation token for interacting with the
    // CAB
    if (delegationToken == null || delegationToken.isEmpty()) {
      throw new IllegalArgumentException(E_MISSING_DT);
    }

    String dtType =
        delegationTokenType != null ? delegationTokenType : DEFAULT_TOKEN_TYPE;
    String accessBrokerAddress = delegationTokenTarget;

    // Treat the configured CAB address as a fallback for the DT-specified
    // address
    if (accessBrokerAddress == null || accessBrokerAddress.isEmpty()) {
      String configuredCABAddress = CABUtils.getCloudAccessBrokerURL(config);
      if (configuredCABAddress != null) {
        accessBrokerAddress = configuredCABAddress;
      }
    }

    if (accessBrokerAddress == null) {
      throw new IllegalStateException(E_MISSING_CAB_ADDR_CONFIG);
    }

    KnoxSession session = null;
    try {
      // Get the GCP credential from the CAB
      session =
          CABUtils.getCloudSession(accessBrokerAddress,
                                   delegationToken,
                                   dtType,
                                   CABUtils.getTrustStoreLocation(config),
                                   CABUtils.getTrustStorePass(config));

      result = CABUtils.getCloudCredentials(config, session);
      if (result != null) {
        LOG.debug("Acquired cloud credentials: token={}, expires={}",
            result.getToken().substring(0, 8),
            new Date(result.getExpirationTimeMilliSeconds()));
      }
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      LOG.error(e.getMessage(), e);
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

}

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

import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_DT_EXPIRATION_OFFSET;

import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.IOUtils;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxToken;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;


public class CloudAccessBrokerTokenProvider implements TokenProvider {

  private static final Logger LOG = LoggerFactory.getLogger(CloudAccessBrokerTokenProvider.class);

  private static final String E_MISSING_DT =
      "Missing required delegation token.";

  private Configuration config;

  private IDBClient<AccessTokenProvider.AccessToken> cabClient;

  // The GCP access token
  private AccessToken accessToken;

  // The amount by which the access token expiration time will be adjusted for evaluation to trigger updating of those
  // access tokens which will be expiring soon.
  private long knoxTokenExpirationOffset;

  private KnoxToken knoxToken;


  /**
   * @param knoxToken             The Knox delegation token
   * @param accessToken           A GCP access token
   * @param accessTokenExpiration The associated GCP access token expiration
   */
  CloudAccessBrokerTokenProvider(IDBClient<AccessTokenProvider.AccessToken> client,
                                 KnoxToken knoxToken,
                                 String accessToken,
                                 Long accessTokenExpiration) {
    this.cabClient = client;
    this.knoxToken = knoxToken;

    if (accessToken != null) {
      this.accessToken = new AccessTokenProvider.AccessToken(accessToken, accessTokenExpiration);
    }
  }

  @Override
  public void setConf(Configuration configuration) {
    this.config = configuration;

    if(configuration != null) {
      this.knoxTokenExpirationOffset =
          configuration.getLong(IDBROKER_DT_EXPIRATION_OFFSET.getPropertyName(), this.knoxTokenExpirationOffset);
    }
  }

  @Override
  public Configuration getConf() {
    return config;
  }

  @Override
  public void updateDelegationToken(KnoxToken delegationToken) {
    knoxToken = delegationToken;
  }

  @Override
  public AccessToken getAccessToken() {
    if (!isValid(accessToken)) {
      LOG.info("No existing valid Google Cloud Platform credentials.");
      try {
        accessToken = fetchAccessToken();
      } catch (IOException e) {
        LOG.error("Failed to fetch new Google Cloud Platform credentials: " + e.getMessage());
        // wrap, again.
        throw new RuntimeException(e);
      }
    } else {
      LOG.info("Using existing Google Cloud Platform credentials");
    }
    return accessToken;
  }

  @Override
  public void refresh() throws IOException {
    LOG.info("Refresh Google Cloud Platform credentials");
    accessToken = fetchAccessToken();
  }

  /**
   * Determine whether the specified access token needs to be updated, based on its expiration time.
   *
   * @param accessToken The AccessToken to evaluate.
   * @return true, if the token has expired, or will be expiring soon; otherwise, false.
   */
  private boolean isValid(AccessToken accessToken) {
    return (accessToken != null) && (accessToken.getExpirationTimeMilliSeconds() >= System.currentTimeMillis() + knoxTokenExpirationOffset);
  }


  /**
   * Request a GCP access token from the CAB.
   *
   * @return An AccessToken, or null.
   * @throws IOException upon failure
   */
  private AccessToken fetchAccessToken() throws IOException {
    AccessToken result;

    if (!cabClient.hasKerberosCredentials() && (knoxToken == null || !knoxToken.isValid())) {
      throw new IllegalStateException(E_MISSING_DT);
    }

    // Use the previously-established delegation token for interacting with the CAB
    CloudAccessBrokerSession session;
    try {
      // Get the cloud credentials from the CAB
      session = cabClient.createKnoxCABSession(knoxToken);

      try {
        LOG.debug("Requesting Google Cloud Platform credentials from the Cloud Access Broker.");
        result = cabClient.fetchCloudCredentials(session);
      } catch (IOException e) {
        LOG.error("Error requesting cloud credentials: " + e.getMessage());
        throw e; // If it's not a token error, just pass it along
      } finally {
        IOUtils.cleanupWithLogger(LOG, session);
      }

      if (result != null) {
        LOG.info("Acquired Google Cloud Platform credentials: token={}, expires={}",
            result.getToken().substring(0, 8),
            new Date(result.getExpirationTimeMilliSeconds()));
      }
    } catch (Exception e) {
      LOG.error(e.getMessage());
      LOG.debug("Failed to get Google Cloud Platform credentials.", e);
      throw new DelegationTokenIOException(e.getMessage(), e);
    }

    return result;
  }

}

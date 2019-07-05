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
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_DT_EXPIRATION_OFFSET;

import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.IOUtils;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxToken;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxTokenMonitor;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;


public class CloudAccessBrokerTokenProvider implements AccessTokenProvider {

  private static final Logger LOG = LoggerFactory.getLogger(CloudAccessBrokerTokenProvider.class);

  private static final String E_MISSING_DT =
      "Missing required delegation token.";

  private Configuration config = null;

  private IDBClient<AccessTokenProvider.AccessToken> cabClient;

  // The GCP access token
  private AccessToken accessToken = null;

  // The amount by which the access token expiration time will be adjusted for evaluation to trigger updating of those
  // access tokens which will be expiring soon.
  private long knoxTokenExpirationOffset;

  private KnoxToken knoxToken;

  private final KnoxTokenMonitor knoxTokenMonitor;


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

    this.knoxTokenExpirationOffset = Long.valueOf(IDBROKER_DT_EXPIRATION_OFFSET.getDefaultValue());
    this.knoxTokenMonitor = new KnoxTokenMonitor();
    startKnoxTokenMonitor();
  }

  @Override
  public void setConf(Configuration configuration) {
    this.config = configuration;

    if(configuration != null) {
      this.knoxTokenExpirationOffset = configuration.getLong(IDBROKER_DT_EXPIRATION_OFFSET.getPropertyName(),
          this.knoxTokenExpirationOffset);
    }
  }

  @Override
  public Configuration getConf() {
    return config;
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

    // Refresh the delegation token, if necessary
    if (shouldUpdateDT()) {
      LOG.info("Updating delegation token to avoid expiration.");
      refreshDT();
    }

    // Use the previously-established delegation token for interacting with the
    // CAB
    if (knoxToken == null || !knoxToken.isValid()) {
      throw new IllegalArgumentException(E_MISSING_DT);
    }

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

  private Pair<KnoxSession, String> getDTSession() throws IOException {
    LOG.debug("Attempting to create a Knox delegation token session using local credentials (kerberos, simple)");
    Pair<KnoxSession, String> sessionDetails = cabClient.createKnoxDTSession(getConf());

    if (sessionDetails.getLeft() == null) {
      LOG.debug("Local credentials are not available, attempting to create a Knox delegation token session using an existing Knox delegation token");
      // Kerberos or simple authentication is not available. Attempt to create a session to the
      // CAB-specific topology using the KnoxToken as the credential...
      sessionDetails = Pair.of(cabClient.createKnoxCABSession(knoxToken), "delegation token");

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
   * @return true, if the DT has expired, or is about to expire; false, otherwise.
   */
  private boolean shouldUpdateDT() {
    return (knoxToken == null) || (knoxToken.isAboutToExpire(knoxTokenExpirationOffset));
  }

  /**
   * Refresh the expired delegation token used for interactions with the CAB.
   *
   * @throws IOException upon failure
   */
  private void refreshDT() throws IOException {
    LOG.info("Getting new delegation token.");

    Pair<KnoxSession, String> sessionDetails = getDTSession();

    KnoxSession session = sessionDetails.getLeft();
    String origin = sessionDetails.getRight();

    RequestDTResponseMessage response;
    try {
      // Request the new DT
      response = cabClient.requestKnoxDelegationToken(session, origin, null);
    } finally {
      IOUtils.cleanupWithLogger(LOG, session);
    }

    LOG.debug("Refreshing delegation token details.");

    // Update the DT details so subsequent credentials requests will use them
    knoxToken = KnoxToken.fromDTResponse(response);

    startKnoxTokenMonitor();
  }

  private void startKnoxTokenMonitor() {
    knoxTokenMonitor.monitorKnoxToken(knoxToken, knoxTokenExpirationOffset, new GetKnoxTokenCommand());
  }

  private class GetKnoxTokenCommand implements KnoxTokenMonitor.GetKnoxTokenCommand {
    @Override
    public void execute(KnoxToken knoxToken) throws IOException {
      refreshDT();
    }
  }
}

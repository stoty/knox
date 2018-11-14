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

import com.google.api.client.util.DateTime;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.shell.KnoxSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;


public class CloudAccessBrokerTokenProvider implements AccessTokenProvider {

  private static final Logger LOG = LoggerFactory.getLogger(CloudAccessBrokerTokenProvider.class);

  private static final String E_MISSING_DT =
      "Missing required delegation token.";

  private static final String E_MISSING_CAB_ADDR_CONFIG =
      "Missing Cloud Access Broker address configuration.";

  private static final String DEFAULT_TOKEN_TYPE = "Bearer";

  private Configuration config = null;

  private AccessToken accessToken = null;

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
    if (accessToken == null) {
      accessToken = fetchAccessToken();
    }
    return accessToken;
  }

  @Override
  public void refresh() throws IOException {
    accessToken = fetchAccessToken();
  }

  private AccessToken fetchAccessToken() {
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
        LOG.debug("Acquired cloud credentials: token=" + result.getToken().substring(0, 8) +
                  ", expires=" + new DateTime(result.getExpirationTimeMilliSeconds()));
      }
    } catch (Exception e) {
      LOG.error(e.getMessage(), e);
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

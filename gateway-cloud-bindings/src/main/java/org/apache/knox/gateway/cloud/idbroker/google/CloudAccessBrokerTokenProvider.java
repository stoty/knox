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

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.DateTime;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.hadoop.conf.Configuration;
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.shell.CredentialCollectionException;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.KnoxTokenCredentialCollector;
import org.apache.knox.gateway.shell.knox.token.Get;
import org.apache.knox.gateway.shell.knox.token.Token;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


public class CloudAccessBrokerTokenProvider implements AccessTokenProvider {

  private static final CloudAccessBrokerBindingMessages logger =
                  MessagesFactory.get(CloudAccessBrokerBindingMessages.class);

  private static JsonFactory jsonFactory = new JacksonFactory();

  private Configuration config = null;

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
    AccessToken result = null;

    // Get a delegation token for interacting with the CAB
    Map<String, String> dt = getDelegationToken();
    String delegationToken     = dt.get("access_token");
    String delegationTokenType = dt.get("token_type");
    String accessBrokerAddress = dt.get("target_url");

    // Treat the configured CAB address as an override of the DT-specified address
    String configuredCABAddress = config.get(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS);
    if (configuredCABAddress != null) {
      accessBrokerAddress = configuredCABAddress;
    }

    if (accessBrokerAddress == null) {
      throw new IllegalStateException("Missing Cloud Access Broker address configuration.");
    }

    KnoxSession session = null;
    try {
      // Get the AWS credential from the CAB
      Map<String, String> headers = new HashMap<>();
      headers.put("Authorization", delegationTokenType + " " + delegationToken);

      session = KnoxSession.login(accessBrokerAddress, headers);

      String responseBody;
      if (Boolean.valueOf(config.get(CloudAccessBrokerBindingConstants.CONFIG_CAB_PREFER_USER_ROLE))) {
        responseBody = getAccessTokenResponseForUser(session);
      } else if (Boolean.valueOf(config.get(CloudAccessBrokerBindingConstants.CONFIG_CAB_PREFER_GROUP_ROLE))) {
        responseBody =
            getAccessTokenResponseForGroup(session,
                                           config.get(CloudAccessBrokerBindingConstants.CONFIG_CAB_PREFERRED_GROUP));
      } else {
        responseBody = getAccessTokenResponse(session);
      }

      if (responseBody != null) {
        Map<String, Object> json = parseJSONResponse(responseBody);
        String accessToken = (String) json.get("accessToken");
        String expireTime = (String) json.get("expireTime");
        result = new AccessToken(accessToken, DateTime.parseRfc3339(expireTime).getValue());
      }
    } catch (Exception e) {
      logger.severe(e);
    } finally {
      try {
        if (session != null) {
          session.shutdown();
        }
      } catch (Exception e) {
        logger.warn(e);
      }
    }

    return result; // TODO: What if result is null? Should return some error response?
  }

  @Override
  public void refresh() throws IOException {

  }

  private Map<String, String> getDelegationToken() {
    Map<String, String> dt = new HashMap<>();

    String delegationTokenType = "Bearer";
    String delegationToken     = null;
    String delegationTokenURL  = null;

    // Check for an existing delegation token from the CAB (ala knoxinit)
    KnoxTokenCredentialCollector dtCollector = new KnoxTokenCredentialCollector();
    try {
      dtCollector.collect();
      delegationToken = dtCollector.string();
      delegationTokenURL = dtCollector.getTargetUrl();
      String tokenType = dtCollector.getTokenType();
      if (tokenType != null) {
        delegationTokenType = tokenType;
      }
    } catch (CredentialCollectionException e) {
      logger.severe(e);
    }

    // If there is no existing delegation token, then check for the configured DT endpoint address
    if (delegationToken == null) {
      String dtAddress = config.get(CloudAccessBrokerBindingConstants.CONFIG_DT_ADDRESS);
      if (dtAddress == null) {
        throw new IllegalStateException("Missing Cloud Access Broker delegation token address configuration.");
      }

      String dtUsername = System.getenv(CloudAccessBrokerBindingConstants.DT_USERNAME_ENV_VAR);
      if (dtUsername == null || dtUsername.isEmpty()) {
        logger.missingDelegationTokenUsername();
        throw new IllegalStateException("Missing Cloud Access Broker delegation token username configuration.");
      }

      String dtPass = System.getenv(CloudAccessBrokerBindingConstants.DT_PASS_ENV_VAR);
      if (dtPass == null || dtPass.isEmpty()) {
        logger.missingDelegationTokenPassword();
        throw new IllegalStateException("Missing Cloud Access Broker delegation token password configuration.");
      }

      KnoxSession dtSession = null;
      try {
        dtSession = KnoxSession.login(dtAddress, dtUsername, dtPass);
        Get.Response res = Token.get(dtSession).now();
        if (res.getStatusCode() == HttpStatus.SC_OK) {
          if (res.getContentLength() > 0) {
            if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
              JsonParser jsonParser = jsonFactory.createJsonParser(res.getString());
              Map<String, Object> json = new HashMap<>();
              jsonParser.parse(json);
              delegationToken = (String) json.get("access_token");
              String targetURL = (String) json.get("target_url");
              if (targetURL != null) {
                delegationTokenURL = targetURL;
              }
              String tokenType = (String) json.get("token_type");
              if (tokenType != null) {
                delegationTokenType = tokenType;
              }
            }
          }
        }
      } catch (Exception e) {
        logger.severe(e);
      } finally {
        try {
          if (dtSession != null) {
            dtSession.shutdown();
          }
        } catch (Exception e) {
          logger.warn(e);
        }
      }
    }

    dt.put("access_token", delegationToken);
    dt.put("token_type", delegationTokenType);
    dt.put("target_url", delegationTokenURL);

    return dt;
  }

  private String getAccessTokenResponse(final KnoxSession session) throws IOException {
    String atResponse = null;

    org.apache.knox.gateway.shell.idbroker.Get.Response res =
                      org.apache.knox.gateway.shell.idbroker.Credentials.get(session).now();
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  private String getAccessTokenResponseForGroup(final KnoxSession session, String group) throws IOException {
    String atResponse = null;

    org.apache.knox.gateway.shell.BasicResponse res =
                      org.apache.knox.gateway.shell.idbroker.Credentials.forGroup(session)
                                                                        .groupName(group)
                                                                        .now();
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  private String getAccessTokenResponseForUser(final KnoxSession session) throws IOException {
    String atResponse = null;

    org.apache.knox.gateway.shell.BasicResponse res =
                      org.apache.knox.gateway.shell.idbroker.Credentials.forUser(session).now();
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  private Map<String, Object> parseJSONResponse(String response) throws IOException {
    Map<String, Object> jsonModel = new HashMap<>();
    JsonParser jsonParser = jsonFactory.createJsonParser(response);
    jsonParser.parse(jsonModel);
    return jsonModel;
  }

}

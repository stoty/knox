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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.util.DateTime;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.shell.KnoxSession;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.*;

class CABUtils {

  static String getCloudAccessBrokerAddress(Configuration conf) {
    String address = conf.getTrimmed(CONFIG_CAB_ADDRESS);
    if (address != null) {
      if (address.endsWith("/")) {
        address = address.substring(0, address.length() - 1);
      }
    }
    return address;
  }

  static String getCloudAccessBrokerURL(Configuration conf) {
    return constructURL(getCloudAccessBrokerAddress(conf),
                        conf.getTrimmed(CONFIG_CAB_PATH));
  }

  static String getDelegationTokenProviderURL(Configuration conf) {
    return constructURL(getCloudAccessBrokerAddress(conf),
                        conf.getTrimmed(CONFIG_CAB_DT_PATH));
  }

  private static String constructURL(String address, String path) {
    String url = null;
    if (StringUtils.isNotEmpty(address) && StringUtils.isNotEmpty(path)) {
      url = address + (!path.startsWith("/") ? "/" : "") + path;
    }
    return url;
  }

  static KnoxSession getCloudSession(String cabAddress,
                                     String delegationToken,
                                     String delegationTokenType)
      throws Exception {
    return getCloudSession(cabAddress,
                           delegationToken,
                           delegationTokenType,
                           null,
                           null);
  }

  static KnoxSession getCloudSession(Configuration config,
                                     String delegationToken,
                                     String delegationTokenType)
      throws Exception {
    return getCloudSession(getCloudAccessBrokerURL(config),
                           delegationToken,
                           delegationTokenType,
                           getTrustStoreLocation(config),
                           getTrustStorePass(config));
  }


  static KnoxSession getCloudSession(String cabAddress,
                                     String delegationToken,
                                     String delegationTokenType,
                                     String trustStoreLocation,
                                     String trustStorePass) throws Exception {
    Map<String, String> headers = new HashMap<>();
    headers.put("Authorization",
                delegationTokenType + " " + delegationToken);
    return KnoxSession.login(cabAddress,
                             headers,
                             trustStoreLocation,
                             trustStorePass);
  }

  static AccessTokenProvider.AccessToken getCloudCredentials(Configuration config,
                                                             KnoxSession session)
    throws IOException {
    AccessTokenProvider.AccessToken result = null;

    String responseBody;
    if (Boolean.valueOf(config.getTrimmed(EMPLOY_USER_ROLE))) {
      // Default role mapping algorithm request
      responseBody = getAccessTokenResponseForUser(session);
    } else if (Boolean.valueOf(config.getTrimmed(CONFIG_CAB_EMPLOY_GROUP_ROLE))) {
      // Explicit group request
      responseBody =
          getAccessTokenResponseForGroup(session,
              config.getTrimmed(CONFIG_CAB_REQUIRED_GROUP));
    } else if (config.getTrimmed(CONFIG_CAB_REQUIRED_GROUP) != null) {
      // Implicit employ group role enablement, with explicit group request
      responseBody =
          getAccessTokenResponseForGroup(session,
                                         config.getTrimmed(CONFIG_CAB_REQUIRED_GROUP));
    } else if (config.getTrimmed(CONFIG_CAB_REQUIRED_ROLE) != null) {
      // Explicit role request
      responseBody =
          getAccessTokenResponseForRole(session,
                                        config.getTrimmed(CONFIG_CAB_REQUIRED_ROLE));
    } else {
      responseBody = getAccessTokenResponse(session);
    }

    if (responseBody != null) {
      Map<String, Object> json = parseJSONResponse(responseBody);
      String accessToken = (String) json.get("accessToken");
      String expireTime = (String) json.get("expireTime");
      long expirationDateTime = DateTime.parseRfc3339(expireTime).getValue();
      result =
          new AccessTokenProvider.AccessToken(accessToken,
                                              expirationDateTime);
    }

    return result;
  }

  static String getAccessTokenResponse(final KnoxSession session) throws IOException {
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

  static String getAccessTokenResponseForGroup(final KnoxSession session,
                                               final String group)
      throws IOException {
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

  static String getAccessTokenResponseForUser(final KnoxSession session) throws IOException {
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

  static String getAccessTokenResponseForRole(final KnoxSession session,
                                              final String role)
      throws IOException {
    String atResponse = null;

    org.apache.knox.gateway.shell.BasicResponse res =
        org.apache.knox.gateway.shell.idbroker.Credentials.forRole(session)
                                                          .roleid(role).now();
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  static Map<String, Object> parseJSONResponse(String response)
      throws IOException {
    ObjectMapper om = new ObjectMapper();
    return om.readValue(response,
                        new TypeReference<Map<String, Object>>(){});
  }

  static String getTrustStoreLocation(Configuration conf) {
    String result;
    result = conf.getTrimmed(CONFIG_CAB_TRUST_STORE_LOCATION);
    if (StringUtils.isEmpty(result)) {
      result = System.getenv(CONFIG_CAB_TRUST_STORE_LOCATION_ENV_VAR);
    }
    return result;
  }

  static String getTrustStorePass(Configuration conf) {
    String result = null;

    // First, check the credential store
    try {
      char[] secret = conf.getPassword(CONFIG_CAB_TRUST_STORE_PASS);
      if (secret != null && secret.length > 0) {
        result = new String(secret);
      }
    } catch (IOException e) {
      //
    }

    if (StringUtils.isEmpty(result)) {
      // Check the environment variable
      result = System.getenv(CONFIG_CAB_TRUST_STORE_PASS_ENV_VAR);
    }

    return result;
  }

}

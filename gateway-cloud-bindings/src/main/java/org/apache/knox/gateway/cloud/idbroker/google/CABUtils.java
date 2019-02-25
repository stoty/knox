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
import com.google.cloud.hadoop.util.AccessTokenProvider;
import com.google.common.base.Preconditions;
import org.apache.knox.gateway.shell.ClientContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.shell.KnoxSession;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.*;

final class CABUtils {

  private static final Logger LOG =
      LoggerFactory.getLogger(CABUtils.class);
  
  private CABUtils() {
  }

  /**
   * Get the URL of the cab
   * @param conf configuration to scan
   * @return the address, with any trailing / stripped
   * @throws IllegalArgumentException if there is none
   */
  static String getCloudAccessBrokerAddress(Configuration conf) 
      throws IllegalArgumentException{
    String address = conf.getTrimmed(CONFIG_CAB_ADDRESS, "");
    if (address.endsWith("/")) {
      address = address.substring(0, address.length() - 1);
    }
    Preconditions.checkArgument(
        !address.isEmpty(),
        "No URL provided in %s", CONFIG_CAB_ADDRESS); 
    return address;
  }

  /**
   * Get URL to the gcp cab service
   * @param conf configuration to read.
   * @return the full URL to the service
   * @throws IllegalArgumentException bad configuration.
   */
  static String getCloudAccessBrokerURL(Configuration conf) {
    return getBrokerURL(conf, 
        CONFIG_CAB_PATH, DEFAULT_CONFIG_CAB_PATH);
  }

  /**
   * Get URL to the dt service
   * @param conf configuration to read.
   * @return the full URL to the service
   * @throws IllegalArgumentException bad configuration.
   */
  static String getDelegationTokenProviderURL(Configuration conf) {
    return getBrokerURL(conf,
        CONFIG_CAB_DT_PATH, DEFAULT_CONFIG_CAB_DT_PATH);
  }

  /**
   * Get the URL to a broker component.
   * @param conf configuration to read.
   * @param key key to the specific path
   * @param defVal default value
   * @return the full URL to the service
   * @throws IllegalArgumentException bad configuration.
   */
  static String getBrokerURL(Configuration conf, String key, String defVal) {
    String v = conf.getTrimmed(key, defVal);
    Preconditions.checkArgument(!v.isEmpty(),
        "No path in %s", key);
    return constructURL(getCloudAccessBrokerAddress(conf), v);
  }

  /**
   * Combine an address and path; guarantee that there is exactly one "/"
   * between the two.
   * @param address address
   * @param path path underneath
   * @return a concatenation of the address +"/" + path
   */
  public static String constructURL(String address, String path) {
    String url = null;
    if (StringUtils.isNotEmpty(address) && StringUtils.isNotEmpty(path)) {

      String a = address;
      if (a.endsWith("/")) {
        a = a.substring(0, a.length() - 1);
      }
      url = a + (!path.startsWith("/") ? "/" : "") + path;
    }
    return url;
  }

  static KnoxSession getCloudSession(String cabAddress,
                                     String delegationToken,
                                     String delegationTokenType)
      throws URISyntaxException {
    return getCloudSession(cabAddress,
                           delegationToken,
                           delegationTokenType,
                           null,
                           null);
  }

  static KnoxSession getCloudSession(Configuration config,
                                     String delegationToken,
                                     String delegationTokenType)
      throws URISyntaxException {
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
                                     String trustStorePass)
      throws URISyntaxException {
    LOG.debug("Establishing Knox session with truststore: " + trustStoreLocation);
    Map<String, String> headers = new HashMap<>();
    headers.put("Authorization", delegationTokenType + " " + delegationToken);
    return KnoxSession.login(cabAddress,
                             headers,
                             trustStoreLocation,
                             trustStorePass);
  }

  static KnoxSession getCloudSession(String cabAddress,
                                     String delegationToken,
                                     String delegationTokenType,
                                     String cabPublicCert)
      throws URISyntaxException {
    LOG.debug("Establishing Knox session with Cloud Access Broker cert: " + cabPublicCert.substring(0, 4) + "...");
    Map<String, String> headers = new HashMap<>();
    headers.put("Authorization", delegationTokenType + " " + delegationToken);
    ClientContext clientCtx = ClientContext.with(cabAddress);
    clientCtx.connection()
             .withPublicCertPem(cabPublicCert);
    KnoxSession session = KnoxSession.login(clientCtx);
    session.setHeaders(headers);
    return session;
  }


  static AccessTokenProvider.AccessToken getCloudCredentials(
      Configuration config, KnoxSession session) throws IOException {
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

  /**
   * Get the the location of the trust store.
   * @param conf
   * @return
   */
  static String getTrustStoreLocation(Configuration conf) {
    String result = conf.getTrimmed(CONFIG_CAB_TRUST_STORE_LOCATION);
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

  /**
   * Get a configuration secret from the conf and then the
   * environment.
   * @param conf configuration file.
   * @param name option name
   * @param envVar environment variable name
   * @return the value
   */
  static String getConfigSecret(final Configuration conf,
      final String name, final String envVar) {
    String value = getAlias(conf, name);

    // Finally, check the environment variable, if one was specified
    if (StringUtils.isEmpty(value) && StringUtils.isNotEmpty(envVar)) {
      value = System.getenv(envVar);
    }
    return value;
  }

  /**
   * Get a configuration secret from the conf and then the
   * environment. If the value is empty or null, an exception
   * is raised.
   * @param conf configuration file.
   * @param name option name
   * @param envVar environment variable name
   * @param errorText text to use in the exception.
   * @return the value
   * @throws IllegalStateException if the secret is missing
   */
  static String getRequiredConfigSecret(final Configuration conf,
      final String name,
      final String envVar,
      final String errorText) {
    String value = getConfigSecret(conf, name, envVar);
    if (StringUtils.isEmpty(value)) {
      LOG.error(errorText);
      throw new IllegalStateException(errorText);
    }
    return value;
  }

  private static String getAlias(final Configuration conf, final String alias) {
    String result = null;
    try {
      char[] aliasValue = conf.getPassword(alias);
      if (aliasValue != null && aliasValue.length > 0) {
        result = new String(aliasValue);
      }
    } catch (IOException e) {
      LOG.info("Error accessing credential alias {}", alias);
      LOG.error("Error accessing credential alias {}", alias, e);
    }
    return result;
  }
}

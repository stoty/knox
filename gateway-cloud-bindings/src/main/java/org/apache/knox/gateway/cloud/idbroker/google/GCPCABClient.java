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
import com.google.cloud.hadoop.fs.gcs.auth.DelegationTokenIOException;
import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.util.JsonSerialization;
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.common.CommonConstants;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.HadoopException;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.apache.knox.gateway.shell.idbroker.Credentials;
import org.apache.knox.gateway.shell.knox.token.Get;
import org.apache.knox.gateway.shell.knox.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.core.MediaType;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_EMPLOY_GROUP_ROLE;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_REQUIRED_GROUP;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_REQUIRED_ROLE;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_DT_PASS;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_DT_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_EMPLOY_USER_ROLE;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.DT_PASS_ENV_VAR;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.DT_USERNAME_ENV_VAR;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.HADOOP_SECURITY_AUTHENTICATION;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.IDBROKER_CREDENTIALS_TYPE;

/**
 * Used for interactions with the Cloud Access Broker services.
 */
public class GCPCABClient implements CloudAccessBrokerClient {

  static final String E_MISSING_DT_ADDRESS =
      "Missing Cloud Access Broker delegation token address configuration"
          + " in " + CONFIG_CAB_DT_PATH;

  static final String E_FAILED_DT_ACQUISITION =
      "Error acquiring delegation token";

  static final String E_FAILED_DT_SESSION =
      "Error establishing session with delegation token provider";

  static final String E_MISSING_DT_USERNAME_CONFIG =
      "Missing Cloud Access Broker delegation token username configuration"
          + " in " + CONFIG_DT_USERNAME;

  static final String E_MISSING_DT_PASS_CONFIG =
      "Missing Cloud Access Broker delegation token password configuration"
          + " in " + CONFIG_DT_PASS;

  private static final String AUTH_HEADER_NAME = "Authorization";

  private static final Logger LOG = LoggerFactory.getLogger(GCPCABClient.class);



  @Override
  public KnoxSession getCloudSession(final String cabAddress,
                                     final String delegationToken,
                                     final String delegationTokenType)
      throws URISyntaxException {
    return getCloudSession(cabAddress,
        delegationToken,
        delegationTokenType,
        null,
        null);
  }

  @Override
  public KnoxSession getCloudSession(final Configuration config,
                                     final String delegationToken,
                                     final String delegationTokenType)
      throws URISyntaxException {
    return getCloudSession(CABUtils.getCloudAccessBrokerURL(config),
        delegationToken,
        delegationTokenType,
        CABUtils.getTrustStoreLocation(config),
        CABUtils.getTrustStorePass(config));
  }


  @Override
  public KnoxSession getCloudSession(final String cabAddress,
                                     final String delegationToken,
                                     final String delegationTokenType,
                                     final String trustStoreLocation,
                                     final String trustStorePass)
      throws URISyntaxException {
    LOG.debug("Establishing Knox session with truststore: " + trustStoreLocation);
    Map<String, String> headers = new HashMap<>();
    headers.put(AUTH_HEADER_NAME, delegationTokenType + " " + delegationToken);
    return KnoxSession.login(cabAddress,
        headers,
        trustStoreLocation,
        trustStorePass);
  }

  @Override
  public KnoxSession getCloudSession(final String cabAddress,
                                     final String delegationToken,
                                     final String delegationTokenType,
                                     final String cabPublicCert)
      throws URISyntaxException {
    LOG.debug("Establishing Knox session with Cloud Access Broker cert: " + cabPublicCert.substring(0, 4) + "...");
    Map<String, String> headers = new HashMap<>();
    headers.put(AUTH_HEADER_NAME, delegationTokenType + " " + delegationToken);
    ClientContext clientCtx = ClientContext.with(cabAddress);
    clientCtx.connection()
        .withPublicCertPem(cabPublicCert);
    KnoxSession session = KnoxSession.login(clientCtx);
    session.setHeaders(headers);
    return session;
  }

  @Override
  public RequestDTResponseMessage requestDelegationToken(final Configuration conf,
                                                         final KnoxSession dtSession) throws IOException {
    RequestDTResponseMessage delegationTokenResponse;

    try {
      String gateway = CABUtils.getCloudAccessBrokerURL(conf); // TODO: PJZ: Can we get the gateway address from the session?
      Get.Request request = Token.get(dtSession);
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
      throw new DelegationTokenIOException(E_FAILED_DT_ACQUISITION + ": " + e, e);
    }

    return delegationTokenResponse;
  }

  /**
   * Update a still-valid delegation token, using only the delegation token for authentication.
   */
  @Override
  public RequestDTResponseMessage updateDelegationToken(final Configuration conf,
                                                        final String delegationToken,
                                                        final String delegationTokenType) throws Exception {
    Map<String, String> headers = new HashMap<>();
    headers.put(AUTH_HEADER_NAME, delegationTokenType + " " + delegationToken);
    return requestDelegationToken(conf, KnoxSession.login(CABUtils.getCloudAccessBrokerURL(conf), headers));
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
  private <T> T processGet(final Class<T> clazz,
                                  final String gateway,
                                  final URI requestURI,
                                  final BasicResponse response) throws IOException {

    int statusCode = response.getStatusCode();
    String type = response.getContentType();

    String dest = requestURI != null? requestURI.toString() : ("path under " + gateway);
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

  /**
   * Create the DT session
   * @return the session
   * @throws IllegalStateException bad state
   */
  @Override
  public KnoxSession createDTSession(Configuration conf,
                                     String gatewayCertificate) throws IllegalStateException {
    String dtAddress = CABUtils.getDelegationTokenProviderURL(conf);
    if (dtAddress == null) {
      throw new IllegalStateException(E_MISSING_DT_ADDRESS);
    }

    KnoxSession session = null;
    // delegation tokens are typically only collected in
    // kerberized scenarios. However, we may find some testing
    // or client side scenarios where it will make more sense to
    // use username and password to acquire the DT from IDBroker.
    boolean dtViaUsernamePassword = conf.get(IDBROKER_CREDENTIALS_TYPE, "kerberos").equals("username-password");

    if (dtViaUsernamePassword || conf.get(HADOOP_SECURITY_AUTHENTICATION, "simple").equalsIgnoreCase("simple")) {
      session = createUsernamePasswordDTSession(conf, dtAddress);
    }
    else if (conf.get(HADOOP_SECURITY_AUTHENTICATION, "simple").equalsIgnoreCase("kerberos")) {
      try {
        session = createKerberosDTSession(conf, dtAddress, gatewayCertificate);
      } catch (URISyntaxException e) {
        throw new IllegalStateException(E_FAILED_DT_SESSION, e);
      }
    }

    return session;
  }

  @Override
  public KnoxSession createUsernamePasswordDTSession(Configuration conf, String dtAddress) {
    KnoxSession session;

    // Check for an alias first (falling back to clear-text in config)
    String dtUsername =
        CABUtils.getRequiredConfigSecret(conf, CONFIG_DT_USERNAME, DT_USERNAME_ENV_VAR, E_MISSING_DT_USERNAME_CONFIG);

    // Check for an alias first (falling back to clear-text in config)
    String dtPass =
        CABUtils.getRequiredConfigSecret(conf, CONFIG_DT_PASS, DT_PASS_ENV_VAR, E_MISSING_DT_PASS_CONFIG);

    try {
      session =
          KnoxSession.login(dtAddress,
              dtUsername,
              dtPass,
              CABUtils.getTrustStoreLocation(conf),
              CABUtils.getTrustStorePass(conf));
    } catch (URISyntaxException e) {
      LOG.error(E_FAILED_DT_SESSION, e);
      throw new IllegalStateException(E_FAILED_DT_SESSION, e);
    }
    return session;
  }

  @Override
  public KnoxSession createKerberosDTSession(final Configuration conf,
                                             final String dtAddress,
                                             final String gatewayCertificate)
      throws URISyntaxException {
    KnoxSession session;

    session =
        KnoxSession.login(ClientContext.with(dtAddress)
            .kerberos()
            .enable(true)
            .jaasConf(conf.get(CloudAccessBrokerBindingConstants.CONFIG_JAAS_FILE, ""))
            .jaasConfEntry(conf.get(CommonConstants.CAB_CLIENT_JAAS_CONF_ENTRY,
                KnoxSession.JGSS_LOGIN_MOUDLE))
            .krb5Conf(conf.get(CloudAccessBrokerBindingConstants.CONFIG_KERBEROS_CONF, ""))
            .debug(LOG.isDebugEnabled())
            .end()
            .connection()
            .withTruststore(CABUtils.getTrustStoreLocation(conf),
                CABUtils.getTrustStorePass(conf))
            .withPublicCertPem(gatewayCertificate)
            .end());
    return session;
  }

  public AccessTokenProvider.AccessToken getCloudCredentials(final Configuration config, final KnoxSession session)
      throws IOException {
    AccessTokenProvider.AccessToken result = null;

    String responseBody;
    try {
      if (Boolean.valueOf(config.getTrimmed(CONFIG_EMPLOY_USER_ROLE))) {
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
    } catch (KnoxShellException e) {
      throw new IOException(e);
    }

    if (responseBody != null) {
      Map<String, Object> json = parseJSONResponse(responseBody);
      String accessToken = (String) json.get("accessToken");
      String expireTime = (String) json.get("expireTime");
      long expirationDateTime = DateTime.parseRfc3339(expireTime).getValue();
      result = new AccessTokenProvider.AccessToken(accessToken, expirationDateTime);
    }

    return result;
  }

  String getAccessTokenResponse(final KnoxSession session) throws IOException {
    String atResponse = null;

    org.apache.knox.gateway.shell.idbroker.Get.Response res = Credentials.get(session).now();
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  String getAccessTokenResponseForGroup(final KnoxSession session,
                                               final String group)
      throws IOException {
    String atResponse = null;

    BasicResponse res =Credentials.forGroup(session)
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

  String getAccessTokenResponseForUser(final KnoxSession session) throws IOException {
    String atResponse = null;

    BasicResponse res = Credentials.forUser(session).now();
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  String getAccessTokenResponseForRole(final KnoxSession session,
                                              final String role)
      throws IOException {
    String atResponse = null;

    BasicResponse res =Credentials.forRole(session).roleid(role).now();
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  Map<String, Object> parseJSONResponse(final String response) throws IOException {
    ObjectMapper om = new ObjectMapper();
    return om.readValue(response, new TypeReference<Map<String, Object>>(){});
  }


}

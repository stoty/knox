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
import org.apache.hadoop.security.KerberosAuthException;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.JsonSerialization;
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.common.CloudAccessBrokerClient;
import org.apache.knox.gateway.cloud.idbroker.common.CommonUtils;
import org.apache.knox.gateway.cloud.idbroker.common.Preconditions;
import org.apache.knox.gateway.cloud.idbroker.common.DefaultRequestExecutor;
import org.apache.knox.gateway.cloud.idbroker.common.RequestExecutor;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
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
import java.security.PrivilegedAction;
import java.util.Arrays;
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
      "Missing Cloud Access Broker delegation token address config"
          + " in " + CONFIG_CAB_DT_PATH;

  static final String E_FAILED_DT_ACQUISITION =
      "Error acquiring delegation token";

  static final String E_FAILED_DT_SESSION =
      "Error establishing session with delegation token provider";

  static final String E_MISSING_DT_USERNAME_CONFIG =
      "Missing Cloud Access Broker delegation token username config"
          + " in " + CONFIG_DT_USERNAME;

  static final String E_MISSING_DT_PASS_CONFIG =
      "Missing Cloud Access Broker delegation token password config"
          + " in " + CONFIG_DT_PASS;

  private static final String AUTH_HEADER_NAME = "Authorization";

  private static final Logger LOG = LoggerFactory.getLogger(GCPCABClient.class);

  private Configuration config;

  private String trustStoreLocation;

  private String trustStorePass;

  private boolean useIDBCertificateFromDT;

  private RequestExecutor requestExecutor;


  public GCPCABClient(Configuration conf) {
    this.config = conf;

    trustStoreLocation = CABUtils.getTrustStoreLocation(conf);
    LOG.debug("Using truststore: {}", trustStoreLocation != null ? trustStoreLocation : "None configured");
    trustStorePass = CABUtils.getTrustStorePass(conf);

    useIDBCertificateFromDT =
        CommonUtils.useCABCertFromDelegationToken(config, CloudAccessBrokerBindingConstants.CONFIG_PREFIX);

    String[] endpoints = conf.getStrings(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS);
    Preconditions.checkState(endpoints != null && endpoints.length > 0,
                                "At least one CloudAccessBroker endpoint must be configured.");
    requestExecutor = new DefaultRequestExecutor(Arrays.asList(endpoints));
  }

  boolean isUseIDBCertificateFromDT() {
    return useIDBCertificateFromDT;
  }

  @Override
  public CloudAccessBrokerSession getCloudSession(final String delegationToken,
                                                  final String delegationTokenType)
      throws URISyntaxException {
    LOG.debug("Establishing Knox session with truststore: " + getTrustStoreLocation());
    String credentialsURL = getCredentialsURL();
    Map<String, String> headers = new HashMap<>();
    headers.put(AUTH_HEADER_NAME, delegationTokenType + " " + delegationToken);
    return CloudAccessBrokerSession.create(credentialsURL,
                                           headers,
                                           getTrustStoreLocation(),
                                           getTrustStorePass());
  }


  public String getCloudAccessBrokerAddress() {
    return requestExecutor.getEndpoint();
  }


  @Override
  public CloudAccessBrokerSession getCloudSession(final String delegationToken,
                                                  final String delegationTokenType,
                                                  final String cabPublicCert)
      throws URISyntaxException {
    Map<String, String> headers = new HashMap<>();
    headers.put(AUTH_HEADER_NAME, delegationTokenType + " " + delegationToken);
    ClientContext clientCtx = ClientContext.with(getCredentialsURL());

    ClientContext.ConnectionContext connContext =
                              clientCtx.connection().withTruststore(getTrustStoreLocation(), getTrustStorePass());
    if (useIDBCertificateFromDT) {
      LOG.debug("Establishing Knox session with Cloud Access Broker cert: " + cabPublicCert.substring(0, 4) + "...");
      connContext.withPublicCertPem(cabPublicCert);
    }
    connContext.end();

    CloudAccessBrokerSession session = CloudAccessBrokerSession.create(clientCtx);
    session.setHeaders(headers);
    return session;
  }

  String getTrustStoreLocation() {
    return trustStoreLocation;
  }

  String getTrustStorePass() {
    return trustStorePass;
  }

  @Override
  public RequestDTResponseMessage requestDelegationToken(final KnoxSession dtSession) throws IOException {
    RequestDTResponseMessage delegationTokenResponse;

    try {
      try {
        delegationTokenResponse = processGet(RequestDTResponseMessage.class,
                                             dtSession.base(),
                                             Token.get(dtSession));
        if (StringUtils.isEmpty(delegationTokenResponse.access_token)) {
          throw new DelegationTokenIOException("No access token from DT login");
        }
      } catch (HadoopException e) {
        // add the URL
        throw new DelegationTokenIOException("From " + dtSession.base() + " : " + e.toString(), e);
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
  public RequestDTResponseMessage updateDelegationToken(final String delegationToken,
                                                        final String delegationTokenType,
                                                        final String cabPublicCert) throws Exception {
    return requestDelegationToken(getCloudSession(delegationToken,
                                                  delegationTokenType,
                                                  cabPublicCert));
  }


  private <T> T processGet(final Class<T> clazz, final String gateway, final Get.Request request) throws IOException {
    BasicResponse response;

    UserGroupInformation user = UserGroupInformation.getLoginUser();
    if (user != null && UserGroupInformation.isSecurityEnabled()) {
      if (LOG.isDebugEnabled()) {
        UserGroupInformation.logAllUserInfo(LOG, user);
      }
      response = user.doAs((PrivilegedAction<BasicResponse>) () -> request.now());
    } else {
      response = request.now();
    }

    return processGet(clazz, gateway, request.getRequestURI(), response);
  }

  /**
   * Handle a GET response by validating headers and status, parsing to the given type.
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

    JsonSerialization<T> serDeser = new JsonSerialization<>(clazz, false, true);
    InputStream stream = response.getStream();
    return serDeser.fromJsonStream(stream);
  }

  /**
   * Create the DT session
   * @return the session
   * @throws IllegalStateException bad state
   */
  @Override
  public KnoxSession createDTSession(String gatewayCertificate) throws IllegalStateException {
    String dtAddress = getDelegationTokenURL();
    if (dtAddress == null) {
      throw new IllegalStateException(E_MISSING_DT_ADDRESS);
    }

    KnoxSession session = null;
    // delegation tokens are typically only collected in
    // kerberized scenarios. However, we may find some testing
    // or client side scenarios where it will make more sense to
    // use username and password to acquire the DT from IDBroker.
    boolean dtViaUsernamePassword = config.get(IDBROKER_CREDENTIALS_TYPE, "kerberos").equals("username-password");

    if (dtViaUsernamePassword || config.get(HADOOP_SECURITY_AUTHENTICATION, "simple").equalsIgnoreCase("simple")) {
      session = createUsernamePasswordDTSession();
    } else if (config.get(HADOOP_SECURITY_AUTHENTICATION, "simple").equalsIgnoreCase("kerberos")) {
      try {
        UserGroupInformation user = UserGroupInformation.getLoginUser();
        if (user != null) {
          ClientContext clientContext = ClientContext.with(dtAddress)
                                                     .withSubjectCredsOnly(true);

          clientContext.kerberos().enable(true); // UserGroupInformation.AuthenticationMethod.KERBEROS.equals(user.getAuthenticationMethod()) ?
          ClientContext.ConnectionContext connContext =
                                    clientContext.connection()
                                                 .withTruststore(getTrustStoreLocation(), getTrustStorePass());
          if (useIDBCertificateFromDT) {
            connContext.withPublicCertPem(gatewayCertificate);
          }
          connContext.end();

          session = CloudAccessBrokerSession.create(clientContext);
        }
      } catch (KerberosAuthException e) {
        LOG.debug("Kerberos authentication error: " + e.getMessage());
      } catch (Exception e) {
        LOG.error("Error establishing Kerberos Knox session for the current user: " + e.getMessage());
      }

      if (session == null) {
        try {
          session = createKerberosDTSession(gatewayCertificate);
        } catch (URISyntaxException e) {
          throw new IllegalStateException(E_FAILED_DT_SESSION, e);
        }
      }
    }

    return session;
  }

  @Override
  public KnoxSession createUsernamePasswordDTSession() {
    KnoxSession session;

    // Check for an alias first (falling back to clear-text in config)
    String dtUsername =
        CABUtils.getRequiredConfigSecret(config, CONFIG_DT_USERNAME, DT_USERNAME_ENV_VAR, E_MISSING_DT_USERNAME_CONFIG);

    // Check for an alias first (falling back to clear-text in config)
    String dtPass =
        CABUtils.getRequiredConfigSecret(config, CONFIG_DT_PASS, DT_PASS_ENV_VAR, E_MISSING_DT_PASS_CONFIG);

    try {
      session = CloudAccessBrokerSession.create(getDelegationTokenURL(),
                                                dtUsername,
                                                dtPass,
                                                getTrustStoreLocation(),
                                                getTrustStorePass());
    } catch (URISyntaxException e) {
      LOG.error(E_FAILED_DT_SESSION, e);
      throw new IllegalStateException(E_FAILED_DT_SESSION, e);
    }
    return session;
  }

  @Override
  public KnoxSession createKerberosDTSession(final String gatewayCertificate)
      throws URISyntaxException {
    ClientContext clientContext =
        ClientContext.with(getDelegationTokenURL())
                     .kerberos()
                     .enable(true)
                     .jaasConf(config.get(CloudAccessBrokerBindingConstants.CONFIG_JAAS_FILE, ""))
                     .krb5Conf(config.get(CloudAccessBrokerBindingConstants.CONFIG_KERBEROS_CONF, ""))
                     .debug(LOG.isDebugEnabled())
                     .end();

    ClientContext.ConnectionContext connContext =
        clientContext.connection().withTruststore(getTrustStoreLocation(), getTrustStorePass());
    if (useIDBCertificateFromDT) {
      connContext.withPublicCertPem(gatewayCertificate);
    }
    connContext.end();

    return CloudAccessBrokerSession.create(clientContext);
  }

  public AccessTokenProvider.AccessToken getCloudCredentials(final CloudAccessBrokerSession session)
      throws IOException {
    AccessTokenProvider.AccessToken result = null;

    String responseBody;
    try {
      if (Boolean.valueOf(config.getTrimmed(CONFIG_EMPLOY_USER_ROLE))) {
        // Default role mapping algorithm request
        LOG.debug("Getting Google Cloud Platform credentials using the user request API.");
        responseBody = getAccessTokenResponseForUser(session);
      } else if (Boolean.valueOf(config.getTrimmed(CONFIG_CAB_EMPLOY_GROUP_ROLE))) {
        // Default group request
        LOG.debug("Getting Google Cloud Platform credentials using the group request API.");
        responseBody =
            getAccessTokenResponseForGroup(session,
                config.getTrimmed(CONFIG_CAB_REQUIRED_GROUP));
      } else if (config.getTrimmed(CONFIG_CAB_REQUIRED_GROUP) != null) {
        // Implicit employ group role enablement, with explicit group request
        LOG.debug("Getting Google Cloud Platform credentials using the explicit group request API.");
        responseBody =
            getAccessTokenResponseForGroup(session,
                config.getTrimmed(CONFIG_CAB_REQUIRED_GROUP));
      } else if (config.getTrimmed(CONFIG_CAB_REQUIRED_ROLE) != null) {
        // Explicit role request
        LOG.debug("Getting Google Cloud Platform credentials using the explicit role request API.");
        responseBody =
            getAccessTokenResponseForRole(session,
                config.getTrimmed(CONFIG_CAB_REQUIRED_ROLE));
      } else {
        LOG.debug("Getting Google Cloud Platform credentials using the default request API.");
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

  private String getAccessTokenResponse(final CloudAccessBrokerSession session) throws IOException {
    String atResponse = null;

    org.apache.knox.gateway.shell.idbroker.Get.Response res = requestExecutor.execute(Credentials.get(session));
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  String getAccessTokenResponseForGroup(final CloudAccessBrokerSession session,
                                        final String                   group)
      throws IOException {
    String atResponse = null;

    BasicResponse res = requestExecutor.execute(Credentials.forGroup(session).groupName(group));
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  private String getAccessTokenResponseForUser(final CloudAccessBrokerSession session) throws IOException {
    String atResponse = null;

    BasicResponse res = requestExecutor.execute(Credentials.forUser(session));
    if (res.getStatusCode() == HttpStatus.SC_OK) {
      if (res.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(res.getContentType())) {
          atResponse = res.getString();
        }
      }
    }

    return atResponse;
  }

  private String getAccessTokenResponseForRole(final CloudAccessBrokerSession session,
                                               final String                   role)
      throws IOException {
    String atResponse = null;

    BasicResponse res = requestExecutor.execute(Credentials.forRole(session).roleid(role));
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

  public String getCredentialsURL() {
    return CABUtils.getCloudAccessBrokerURL(config, getCloudAccessBrokerAddress());
  }

  public String getDelegationTokenURL() {
    return CABUtils.getDelegationTokenProviderURL(config, getCloudAccessBrokerAddress());
  }

}

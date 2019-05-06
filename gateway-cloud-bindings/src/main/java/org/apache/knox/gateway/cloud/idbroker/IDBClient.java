/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.knox.gateway.cloud.idbroker;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.file.AccessDeniedException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.google.common.annotations.VisibleForTesting;
import org.apache.knox.gateway.cloud.idbroker.common.Preconditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.DelegationTokenIOException;
import org.apache.hadoop.fs.s3a.commit.DurationInfo;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.hadoop.util.JsonSerialization;
import org.apache.http.HttpResponse;
import org.apache.knox.gateway.cloud.idbroker.messages.AuthResponseAWSMessage;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.cloud.idbroker.messages.ValidationFailure;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.apache.knox.gateway.shell.idbroker.Credentials;
import org.apache.knox.gateway.shell.knox.token.Get;
import org.apache.knox.gateway.shell.knox.token.Token;

import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkArgument;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkState;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.*;

/**
 * This class tries to wrap up all the operations which the DT client
 * will do, so that they can be tested on their own, and to merge
 * common code, such as the validation of HTTP responses.
 * 
 * It has two operational modes:
 * <ol>
 *   <li>
 *     "full" client, which is of the IDB services and authenticating
 *     with kerberos to an IDB endpoint.
 *   </li>
 *   <li>
 *     "light client" which doesn't have the settings to do that,
 *      and instead takes an IDB DT and other configuration information
 *     to ask for secrets from the cloud token provider services.
 *   </li>
 * </ol>
 */
public class IDBClient implements IdentityBrokerClient {

  protected static final Logger LOG =
      LoggerFactory.getLogger(IDBClient.class);

  /**
   * Error message when trying to make calls of an IDB gateway but the
   * client was not configured with one.
   */
  public static final String E_IDB_GATEWAY_UNDEFINED = "IDB gateway is undefined";

  public static final String E_NO_GATEWAY_IN_CONFIGURATION =
      E_IDB_GATEWAY_UNDEFINED + " in " + IDBROKER_GATEWAY;

  public static final String E_NO_PRINCIPAL
      = "Unable to obtain Principal Name for authentication";

  public static final String E_NO_KAUTH
      = " -trying to request full IDBroker session but not logged in with Kerbers.";

  private String gateway;

  private String truststore;

  private String truststorePass;

  /** URL to ask for IDB delegation tokens. */
  private String idbTokensURL;

  /** URL to ask for AWS Credentials. */
  private String awsCredentialsURL;

  private String specificGroup;
  private String specificRole;
  private String onlyUser;
  private String onlyGroups;

  private String origin;

  private UserGroupInformation owner;

  /**
   * Create a full IDB Client, configured to be able to talk to
   * the gateway to request new IDB tokens.
   * @param conf Configuration to use.
   * @param owner owner of the client.
   * @return a new instance.
   * @throws IOException IO problems.
   */
  public static IDBClient createFullIDBClient(
      final Configuration conf,
      final UserGroupInformation owner)
      throws IOException {
    IDBClient client = new IDBClient(conf, owner);
    client.origin = "full client";
    return client;
  }

  /**
   * Create a light IDB Client, only able to talk to CAB endpoints
   * with information coming from the parsed DTs themselves.
   * @param conf Configuration to use.
   * @return a new instance.
   * @throws IOException IO problems.
   */
  public static IDBClient createLightIDBClient(Configuration conf)
      throws IOException {
    IDBClient client = new IDBClient();
    client.origin = "thin client";
    return client;
  }

  /**
   * Create with a call to {@link #initializeAsFullIDBClient(Configuration, UserGroupInformation)}.
   * This is used in the mocking tests so is public.
   *
   * @param conf Configuration to drive off.
   */
  @VisibleForTesting
  IDBClient(
      final Configuration conf,
      final UserGroupInformation owner) throws IOException {
    initializeAsFullIDBClient(conf, owner);
  }

  /**
   * Create without any initialization.
   */
  private IDBClient() {
  }

  /**
   * Initialize the connection as a full IDB Client capable of talking
   * to IDBroker, authenticating with kerberos, and asking for new
   * credentials.
   * @param conf Configuration to use.
   * @throws IOException IO problems.
   */
  private void initializeAsFullIDBClient(
      final Configuration conf,
      final UserGroupInformation owner) throws IOException {
    this.owner = owner;
    this.gateway = maybeAddTrailingSlash(
        conf.getTrimmed(IDBROKER_GATEWAY,
            IDBROKER_GATEWAY_DEFAULT));
    // quick sanity check , is that a URL with a resolvable hostname.
    if (gateway.isEmpty()) {
      throw new DelegationTokenIOException(E_NO_GATEWAY_IN_CONFIGURATION);
    }
    String host = gateway;
    int port = 0;
    try {
      URI uri = new URI(gateway);
      host = uri.getHost();
      port = uri.getPort();
      if (isEmpty(host)) {
        throw new DelegationTokenIOException("Not a valid URI: " + gateway);
      }
      InetAddress[] addresses = InetAddress.getAllByName(host);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Address of IDBroker service {}", 
            Arrays.toString(addresses));
      }
    } catch (UnknownHostException e) {
      throw setCause(new UnknownHostException(gateway), e);
    } catch (URISyntaxException e) {
      throw new DelegationTokenIOException("Not a valid URI: " + gateway, e);
    }
    LOG.debug("IDbroker gateway is {}", gateway);
    String aws = conf.getTrimmed(IDBROKER_AWS_PATH,
        IDBROKER_AWS_PATH_DEFAULT);
    this.awsCredentialsURL = gateway + aws;
    LOG.debug("IDbroker AWS Credentials URL is {}", awsCredentialsURL);

    String dt = conf.getTrimmed(IDBROKER_DT_PATH,
        IDBROKER_DT_PATH_DEFAULT);
    this.idbTokensURL = gateway + dt;
    LOG.debug("IDbroker Knox Tokens URL is {}", idbTokensURL);

    truststore = conf.getTrimmed(IDBROKER_TRUSTSTORE_LOCATION,
        DEFAULT_CERTIFICATE_PATH);
    LOG.debug("Trust store is {}", 
        truststore != null ? truststore : ("unset -using default path"));
    if (truststore != null) {
      File f = new File(truststore);
      if (!f.exists()) {
        throw new FileNotFoundException("Truststore defined in "
            + IDBROKER_TRUSTSTORE_LOCATION + " not found: "
            + f.getAbsolutePath());
      }
    }

    try {
      char[] trustPass = conf.getPassword(IDBROKER_TRUSTSTORE_PASS);
      if (trustPass != null) {
        truststorePass = new String(trustPass);
      }
    } catch (IOException e) {
      LOG.debug("Problem with Configuration.getPassword()", e);
      truststorePass = IDBConstants.DEFAULT_CERTIFICATE_PASSWORD;
    }

    specificGroup = conf.get(IDBROKER_SPECIFIC_GROUP_METHOD, null);
    specificRole = conf.get(IDBROKER_SPECIFIC_ROLE_METHOD, null);
    onlyGroups = conf.get(IDBROKER_ONLY_GROUPS_METHOD, null);
    onlyUser = conf.get(IDBROKER_ONLY_USER_METHOD, null);

    LOG.debug("Created client to {}", gateway);
  }

  protected static String maybeAddTrailingSlash(final String gw) {
    return gw.endsWith("/") ? gw : (gw + "/");
  }

  /**
   * Check that the gateway is configured.
   * If it is not set, then this IDB client was not initialized
   * as a full client.
   */
  private void checkGatewayConfigured() {
    checkState(gateway != null & !gateway.isEmpty(),
        E_IDB_GATEWAY_UNDEFINED);
  }

  public String getGateway() {
    return gateway;
  }

  public String getTruststorePath() {
    return truststore;
  }

  public String getTruststorePass() {
    return truststorePass;
  }

  public String getAwsCredentialsURL() {
    return awsCredentialsURL;
  }

  public String getIdbTokensURL() {
    return idbTokensURL;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("IDBClient{");
    sb.append("gateway='").append(gateway).append('\'');
    sb.append('}');
    return sb.toString();
  }

  /**
   * Build some AWS credentials from the Knox AWS endpoint's response.
   * @param responseAWSStruct parsed JSON response
   * @return the AWS credentials
   * @throws IOException failure
   */
  @Override
  public MarshalledCredentials extractCredentialsFromAWSResponse(
      final AuthResponseAWSMessage responseAWSStruct)
      throws IOException {
    AuthResponseAWSMessage.CredentialsStruct responseCreds
        = responseAWSStruct.Credentials;
    final MarshalledCredentials received =
        new MarshalledCredentials(
            responseCreds.AccessKeyId,
            responseCreds.SecretAccessKey,
            responseCreds.SessionToken);
    received.setExpiration(responseCreds.Expiration);
    received.setRoleARN(responseAWSStruct.AssumedRoleUser.Arn);
    received.validate(gateway + " ",
        MarshalledCredentials.CredentialTypeRequired.SessionOnly);
    return received;
  }

  /**
   * @see IdentityBrokerClient#cloudSessionFromDT(String, String)
   */
  @Override
  public KnoxSession cloudSessionFromDT(String delegationToken,
      final String endpointCert)
      throws IOException {
    checkGatewayConfigured();
    return createKnoxSession(
        delegationToken,
        getAwsCredentialsURL(),
        endpointCert,
        !endpointCert.isEmpty());
  }

  /**
   * @see IdentityBrokerClient#cloudSessionFromDelegationToken(String, String, String)
   */
  @Override
  public KnoxSession cloudSessionFromDelegationToken(
      final String delegationToken,
      final String endpoint,
      final String endpointCert)
      throws IOException {
    return createKnoxSession(delegationToken, endpoint, endpointCert, true);
  }

  private KnoxSession createKnoxSession(
    final String delegationToken,
    final String endpoint,
    final String endpointCert,
    final boolean useEndpointCertificate)
      throws IOException {

    checkArgument(StringUtils.isNotEmpty(delegationToken),
        "Empty delegation token");
    checkArgument(useEndpointCertificate && StringUtils.isNotEmpty(endpointCert),
        "Empty endpoint certificate");
    checkArgument(StringUtils.isNotEmpty(endpoint),
        "Empty endpoint");
    LOG.debug("Establishing Knox session with Cloud Access Broker at {}" 
        + " cert: {}",
        endpoint,
        endpointCert.substring(0, 4));
    Map<String, String> headers = new HashMap<>();
    String delegationTokenType = "Bearer";
    headers.put("Authorization", delegationTokenType + " " + delegationToken);
    ClientContext clientCtx = ClientContext.with(endpoint);
    ClientContext.ConnectionContext connection =
        clientCtx.connection()
                 .withTruststore(getTruststorePath(), getTruststorePass());
    if (useEndpointCertificate) {
      LOG.debug("Using the supplied endpoint certificate");
      connection.withPublicCertPem(endpointCert);
    }
    try (DurationInfo ignored = new DurationInfo(LOG,
          "Logging in to %s", endpoint)) {
      KnoxSession session = KnoxSession.login(clientCtx);
      session.setHeaders(headers);
      return session;
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  /**
   * Create the knox session.
   * @param headers map of headers.
   * @return the new session.
   * @see IdentityBrokerClient#cloudSession(Map) 
   * @throws IOException failure
   */
  @Override
  public KnoxSession cloudSession(Map<String, String> headers)
      throws IOException {
    String url = getAwsCredentialsURL();
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Logging in to %s", url)) {
      return KnoxSession.login(url,
                               headers,
                               getTruststorePath(),
                               getTruststorePass());
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  /**
   * Create a Knox session from a username and password.
   * @param username username
   * @param password pass
   * @return the session
   * @throws IOException failure
   */
  public KnoxSession knoxSessionFromSecrets(String username, String password)
      throws IOException {
    checkGatewayConfigured();
    if (isEmpty(username)) {
      throw new AccessDeniedException("No IDBroker Username");
    }

    String url = getIdbTokensURL();
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Logging in to %s as %s", url, username)) {
      return KnoxSession.login(url,
                               username,
                               password,
                               getTruststorePath(),
                               getTruststorePass());
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  /**
   * Create a session bonded to the knox DT URL via Kerberos auth.
   * @return the session
   * @throws IOException failure
   */
  public KnoxSession knoxSessionFromKerberos()
      throws IOException {
    checkGatewayConfigured();
    String url = getIdbTokensURL();
    Preconditions.checkNotNull(url, "No DT URL specified");
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Logging in to %s", url)) {
      // log in, with debug enabled if this class is logging at debug.
      ClientContext clientContext = ClientContext.with(url);
      clientContext.kerberos()
                   .enable(true)
                   .debug(LOG.isDebugEnabled());
      clientContext.connection()
                   .withTruststore(getTruststorePath(), getTruststorePass())
                   .end();
      return KnoxSession.login(clientContext);
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
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
  public <T> T processGet(final Class<T> clazz,
      @Nullable final URI requestURI,
      final BasicResponse response) throws IOException {

    int statusCode = response.getStatusCode();
    String type = response.getContentType();

    String dest = requestURI != null 
        ? requestURI.toString()
        : ("path under " + gateway);
    if (statusCode != 200) {
      String body = response.getString();
      LOG.error("Bad response {} content-type {}\n{}", statusCode, type,
          body);
      ValidationFailure.verify(false,
          "Wrong status code %s from session auth to %s: %s",
          statusCode, dest, body);
    }
    // fail if there is no data
    ValidationFailure.verify(response.getContentLength() > 0,
        "No content in response from %s; content type %s", 
        dest, type);

    if (!IDBConstants.MIME_TYPE_JSON.equals(type)) {
      String body = response.getString();
      LOG.error("Bad response {} content-type {}\n{}", statusCode, type,
          body);
      ValidationFailure.verify(false,
          "Wrong content type %s from session auth under %s: %s",
          type, gateway, body);
    }

    JsonSerialization<T> serDeser = new JsonSerialization<>(clazz,
        false, true);
    InputStream stream = response.getStream();
    return serDeser.fromJsonStream(stream);
  }

  /**
   * Fetch the AWS Credentials.
   * @param session Knox session
   * @return the credentials.
   * @throws IOException failure
   */
  @Override
  public MarshalledCredentials fetchAWSCredentials(KnoxSession session)
      throws IOException {
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Fetching AWS credentials from %s", session.base())) {
      BasicResponse basicResponse = null;
      IdentityBrokerClient.IDBMethod method = determineIDBMethodToCall();
      switch (method) {
      case DEFAULT:
        basicResponse = Credentials.get(session).now();
        break;
      case SPECIFIC_GROUP:
        basicResponse = Credentials.forGroup(session).groupName(
            specificGroup).now();
        break;
      case SPECIFIC_ROLE:
        basicResponse = Credentials.forRole(session).roleid(
            specificRole).now();
        break;
      case GROUPS_ONLY:
        basicResponse = Credentials.forGroup(session).now();
        break;
      case USER_ONLY:
        basicResponse = Credentials.forUser(session).now();
        break;
      }
      return extractCredentialsFromAWSResponse(
          processGet(AuthResponseAWSMessage.class,
              null, basicResponse));
    }
  }

  /**
   *  Decide what IDB method to use.
   *  @see org.apache.knox.gateway.cloud.idbroker.IdentityBrokerClient#determineIDBMethodToCall()
   */
  @Override
  public IDBMethod determineIDBMethodToCall() {
    IDBMethod method = IDBMethod.DEFAULT;
    if (specificGroup != null) {
      method = IDBMethod.SPECIFIC_GROUP;
    }
    if (specificRole != null) {
      method = IDBMethod.SPECIFIC_ROLE;
    }
    if (onlyUser != null) {
      method = IDBMethod.USER_ONLY;
    }
    if (onlyGroups != null) {
      method = IDBMethod.GROUPS_ONLY;
    }
    return method;
  }

  /** 
   * Ask for a token. 
   * @see IdentityBrokerClient#requestKnoxDelegationToken(KnoxSession)
   */
  @Override
  public RequestDTResponseMessage requestKnoxDelegationToken(
      final KnoxSession knoxSession,
      final String origin,
      final URI fsUri)
      throws IOException {
    Get.Request request = Token.get(knoxSession);
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Fetching IDB access token from %s (session origin %s)",
        request.getRequestURI(), origin)) {
      try {

        RequestDTResponseMessage struct = processGet(
            RequestDTResponseMessage.class,
            request.getRequestURI(),
            request.now());
        String access_token = struct.access_token;
        ValidationFailure.verify(StringUtils.isNotEmpty(access_token),
            "No access token from knox login of %s (session origin %s)",
            request.getRequestURI(), origin);
        return struct;
      } catch (KnoxShellException e) {
        // add the URL
        throw translateException(request.getRequestURI(),
            "origin=" + origin + "; " + buildDiagnosticsString(fsUri, owner),
            e);
      }
    }
  }

  /**
   * Translate an a Knox exception into an IOException, using HTTP error
   * codes if present.
   * @param requestURI URI of the request.
   * @param extraDiags any extra text, or "".
   * @param e exception
   * @return an exception to throw.
   */
  public static IOException translateException(
      URI requestURI,
      String extraDiags,
      KnoxShellException e) {
    String path = requestURI.toString();
    Throwable cause = e.getCause();
    IOException ioe;

    if (cause instanceof ErrorResponse) {
      ErrorResponse error = (ErrorResponse) cause;
      HttpResponse response = error.getResponse();
      int status = response.getStatusLine().getStatusCode();
      String message = String.format("Error %03d from %s", status, path);
      if (!extraDiags.isEmpty()) {
        message += " " + extraDiags;
      }
      switch (status) {
      case 401:
      case 403:
        ioe = new AccessDeniedException(path, null, message);
        ioe.initCause(e);
        break;
      // the object isn't there
      case 404:
      case 410:
        ioe = new FileNotFoundException(message);
        ioe.initCause(e);
        break;
      default:
        ioe = new DelegationTokenIOException(message + "  " + e, e);
      }
    } else {
      // some other error message.
      String errorMessage = e.toString();
      if (errorMessage.contains(E_NO_PRINCIPAL)) {
        errorMessage += E_NO_KAUTH;
      }
      ioe = new DelegationTokenIOException("From " + path
          + " " + errorMessage
          + (extraDiags.isEmpty() ? "" : (" " + extraDiags)),
          e);
    }
    return ioe;
  }

  private static Throwable innermostCause(Throwable ex) {
    if (ex.getCause() == null) {
      return ex;
    } else {
      return innermostCause(ex.getCause());
    }
  }

  /**
   * Take a token and print a secure subset of it.
   * @param accessToken access token.
   * @return the string.
   */
  public static String tokenToPrintableString(String accessToken) {
    return StringUtils.isNotEmpty(accessToken)
        ? (accessToken.substring(0, 4) + "...")
        : "(unset)";
  }

  public static <T extends Exception> T setCause(T ex, Throwable t) {
    ex.initCause(t);
    return ex;
  }

  /**
   * Build a diagnostics string for including in error messages.
   * @param uri FS URI.
   * @param user User
   * @return a string for exceptions; includes user, token info
   */
  public static String buildDiagnosticsString(
      final URI uri,
      final UserGroupInformation user) {
    final StringBuffer diagnostics = new StringBuffer();
    diagnostics.append("filesystem =").append(uri).append("; ");
    diagnostics.append("owner=")
        .append(user != null ? user.getUserName() : "(null)")
        .append("; ");
    if (user != null) {
      diagnostics.append("tokens=[");
      Collection<org.apache.hadoop.security.token.Token<? extends TokenIdentifier>>
          tokens = user.getTokens();
      for (org.apache.hadoop.security.token.Token<? extends TokenIdentifier> token : tokens) {
        diagnostics.append(token.toString()).append(";");
      }
      diagnostics.append("]");
    }
    return diagnostics.toString();
  }
}

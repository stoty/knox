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

import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.DEFAULT_PROPERTY_NAME_SSL_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.DEFAULT_PROPERTY_NAME_SSL_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkArgument;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkNotNull;
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkState;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.hadoop.util.JsonSerialization;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.util.EntityUtils;
import org.apache.knox.gateway.cloud.idbroker.common.CommonUtils;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxToken;
import org.apache.knox.gateway.cloud.idbroker.common.Preconditions;
import org.apache.knox.gateway.cloud.idbroker.common.DefaultRequestExecutor;
import org.apache.knox.gateway.cloud.idbroker.common.RequestExecutor;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.cloud.idbroker.messages.ValidationFailure;
import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.apache.knox.gateway.shell.idbroker.Credentials;
import org.apache.knox.gateway.shell.knox.token.CloudAccessBrokerTokenGet;
import org.apache.knox.gateway.shell.knox.token.Get;
import org.apache.knox.gateway.shell.knox.token.Token;
import org.apache.knox.gateway.util.Tokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.net.ssl.SSLHandshakeException;
import javax.ws.rs.core.MediaType;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.AccessDeniedException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * AbstractIDBClient is an abstract class implementing the operations that an IDBroker client will
 * perform.
 * <p>
 * It has two operational modes:
 * <ol>
 * <li>
 * "full" client, which is of the IDB services and authenticating
 * with kerberos to an IDB endpoint.
 * </li>
 * <li>
 * "light client" which doesn't have the settings to do that,
 * and instead takes an IDB DT and other configuration information
 * to ask for secrets from the cloud token provider services.
 * </li>
 * </ol>
 *
 * @param <CloudCredentialType> the type of value returned for the relevant cloud storage access token
 */
public abstract class AbstractIDBClient<CloudCredentialType> implements IDBClient<CloudCredentialType> {

  private static final Logger LOG = LoggerFactory.getLogger(AbstractIDBClient.class);

  /**
   * Error message when trying to make calls of an IDB gateway but the
   * client was not configured with one.
   */
  protected static final String E_IDB_GATEWAY_UNDEFINED = "No IDB gateways have been defined";

  protected static final String E_NO_PRINCIPAL = "Unable to obtain Principal Name for authentication";

  protected static final String E_NO_KAUTH = "Trying to request full IDBroker session but not logged in with Kerberos.";

  private Configuration config;

  protected RequestExecutor requestExecutor;

  private boolean useCertificateFromDT;

  private String truststore;

  private String truststorePass;

  private String specificGroup;
  private String specificRole;
  private boolean onlyUser;
  private boolean onlyGroups;

  private UserGroupInformation owner;
  private String proxyUser;

  protected AbstractIDBClient(
      final Configuration configuration,
      final UserGroupInformation owner) throws IOException {
    initializeAsFullIDBClient(configuration, owner);
  }

  /**
   * Create without any initialization.
   */
  protected AbstractIDBClient() {

  }

  public List<String> getGatewayBaseURLs() {
    return requestExecutor.getConfiguredEndpoints();
  }

  public String getTruststorePath() {
    return truststore;
  }

  public String getTruststorePassword() {
    return truststorePass;
  }

  public String getCredentialsURL() {
    checkGatewayConfigured();
    return getCredentialsURL(config);
  }

  public String getIdbTokensURL() {
    checkGatewayConfigured();
    return getDelegationTokensURL(config);
  }

  @Override
  public boolean hasKerberosCredentials() {
    return ((owner != null ) && owner.hasKerberosCredentials());
  }

  @Override
  public boolean shouldUseKerberos() {
    return hasKerberosCredentials() && !preferKnoxTokenOverKerberos(config);
  }

  @Override
  public Pair<KnoxSession, String> createKnoxDTSession(Configuration configuration) throws IOException {
    KnoxSession session = null;
    String sessionOrigin = null;

    // delegation tokens are typically only collected in
    // kerberized scenarios. However, we may find some testing
    // or client side scenarios where it will make more sense to
    // use username and password to acquire the DT from IDBroker.
    String credentialsType = getCredentialsType(configuration);
    LOG.debug("IDBroker credentials type is {}", credentialsType);
    boolean useBasicAuth = credentialsType.equals(IDBConstants.IDBROKER_CREDENTIALS_BASIC_AUTH);

    String hadoopAuth = configuration.get(IDBConstants.HADOOP_SECURITY_AUTHENTICATION, IDBConstants.HADOOP_AUTH_SIMPLE);
    boolean isSimpleAuth = IDBConstants.HADOOP_AUTH_SIMPLE.equalsIgnoreCase(hadoopAuth);

    if (useBasicAuth || isSimpleAuth) {
      LOG.debug("Authenticating with IDBroker for DT session via username and password");

      String errorPrefix = useBasicAuth
          ? "Authentication with username and password enabled"
          : "No kerberos session -falling back to username and password";

      String username = getUsername(configuration);
      if (StringUtils.isEmpty(username)) {
        throw new IOException(errorPrefix +
            " -missing configuration option: " + getUsernamePropertyName());
      }

      String password = getPassword(configuration);
      if (StringUtils.isEmpty(password)) {
        throw new IOException(errorPrefix +
            " -missing configuration option: " + getPasswordPropertyName());
      }

      sessionOrigin = "local credentials";
      session = createKnoxDTSession(username, password);
    } else if (IDBConstants.HADOOP_AUTH_KERBEROS.equalsIgnoreCase(hadoopAuth)) {
      LOG.debug("Authenticating with IDBroker requires Kerberos");

      if (hasKerberosCredentials()) {
        LOG.debug("Kerberos credentials are available, using Kerberos to establish a session.");
        sessionOrigin = "local kerberos";
        session = createKnoxDTSession(owner);
      } else {
        LOG.debug("Kerberos credentials are not available, unable to establish a session.");
      }
    } else {
      // no match on either option
      // Current;
      LOG.warn("Unknown IDBroker authentication mechanism, unable to establish a session: \"{}\"", hadoopAuth);
    }

    return Pair.of(session, sessionOrigin);
  }

  /**
   * @see IDBClient#createKnoxCABSession(KnoxToken)
   */
  @Override
  public CloudAccessBrokerSession createKnoxCABSession(final KnoxToken knoxToken) throws IOException {
    if (knoxToken == null) {
      LOG.debug("Creating Knox CAB session using Kerberos...");
      return createKnoxCABSessionUsingKerberos();
    } else {
      LOG.debug("Creating Knox CAB session using Knox DT {} ...", Tokens.getTokenDisplayText(knoxToken.getAccessToken()));
      return createKnoxCABSession(knoxToken.getAccessToken(), knoxToken.getTokenType(), knoxToken.getEndpointPublicCert());
    }
  }

  /**
   * @see IDBClient#createKnoxCABSession(String, String)
   */
  @Override
  public CloudAccessBrokerSession createKnoxCABSession(final String delegationToken,
                                                       final String endpointCert)
      throws IOException {
    return createKnoxSession(delegationToken, getCredentialsURL(), endpointCert, useCertificateFromDT);
  }

  /**
   * @see IDBClient#createKnoxCABSession(String, String, String)
   */
  @Override
  public CloudAccessBrokerSession createKnoxCABSession(final String delegationToken,
                                                       final String delegationTokenType,
                                                       final String endpointCert)
      throws IOException {
    return createKnoxSession(delegationToken,
        delegationTokenType,
        getCredentialsURL(),
        endpointCert,
        useCertificateFromDT);
  }

  /**
   * Create a session bonded to the knox DT URL via Kerberos auth.
   *
   * @return the session
   * @throws IOException failure
   */
  @Override
  public KnoxSession createKnoxDTSession() throws IOException {
    String url = getIdbTokensURL();
    Preconditions.checkNotNull(url, "No DT URL specified");
    try {
      LOG.debug("Logging in to {} using Kerberos", url);
      return CloudAccessBrokerSession.create(createKnoxClientContext(url, true));
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  /**
   * Create a session bonded to the knox DT URL via Kerberos auth.
   *
   * @param user the user to perform the action as
   * @return the session
   * @throws IOException failure
   */
  @Override
  public KnoxSession createKnoxDTSession(UserGroupInformation user) throws IOException {
    if (user == null) {
      return createKnoxDTSession();
    } else {
      try {
        return user.doAs((PrivilegedExceptionAction<KnoxSession>) this::createKnoxDTSession);
      } catch (InterruptedException e) {
        throw new IOException(e);
      }
    }
  }

  /**
   * Create a Knox session from a username and password.
   *
   * @param username username
   * @param password pass
   * @return the session
   * @throws IOException failure
   */
  @Override
  public KnoxSession createKnoxDTSession(String username, String password)
      throws IOException {

    if (isEmpty(username)) {
      throw new AccessDeniedException("No IDBroker Username");
    }

    String url = getIdbTokensURL();
    try {
      LOG.debug("Logging in to {} as {}", url, username);
      return CloudAccessBrokerSession.create(createKnoxClientContext(url, username, password));
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  @Override
  public KnoxSession createKnoxDTSession(KnoxToken knoxToken)
      throws IOException {
    String url = getIdbTokensURL();

    LOG.debug("Logging in to {} using a Knox DT", url);
    return createKnoxSession(knoxToken, url, useCertificateFromDT);
  }

  /**
   * Fetch the Credentials.
   *
   * @param session Knox session
   * @return the credentials.
   * @throws IOException failure
   */
  @Override
  public CloudCredentialType fetchCloudCredentials(CloudAccessBrokerSession session)
      throws IOException {
    LOG.debug("Fetching cloud credentials from {}", session.base());
    AbstractCloudAccessBrokerRequest<? extends BasicResponse> request;

    IDBClient.IDBMethod method = determineIDBMethodToCall();
    switch (method) {
      case SPECIFIC_GROUP:
        request = Credentials.forGroup(session).groupName(specificGroup);
        break;
      case SPECIFIC_ROLE:
        request = Credentials.forRole(session).roleid(specificRole);
        break;
      case GROUPS_ONLY:
        request = Credentials.forGroup(session);
        break;
      case USER_ONLY:
        request = Credentials.forUser(session);
        break;
      case DEFAULT:
      default:
        request = Credentials.get(session);
        break;
    }

    BasicResponse response = null;
    try {
      if (shouldUseKerberos()) {
        // CDPD-3149
        if (owner.isFromKeytab()) {
          owner.checkTGTAndReloginFromKeytab();
        } else {
          owner.reloginFromTicketCache();
        }
        response = owner.doAs((PrivilegedAction<BasicResponse>) () -> requestExecutor.execute(request));
      } else {
        response = requestExecutor.execute(request);
      }
    } catch (ErrorResponse e) {
      HttpResponse r = e.getResponse();
      if (r.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
        HttpEntity entity = r.getEntity();
        if (entity != null) {
          String responseContent = EntityUtils.toString(entity);
          LOG.error("Cloud Access Broker response: " + responseContent);
          if (entity.getContentType().getValue().contains(MediaType.APPLICATION_JSON)) {
            throw new IOException(parseErrorResponse(responseContent));
          }
        }
      }
      throw e;
    }

    return extractCloudCredentialsFromResponse(response);
  }

  private String parseErrorResponse(final String response) {
    StringWriter message = new StringWriter();

    try {
      ObjectMapper om = new ObjectMapper();
      Map<String, String> json = om.readValue(response, new TypeReference<Map<String, String>>(){});
      message.append(json.get("error"));

      String authId = json.get("auth_id");
      if (authId != null && !authId.isEmpty()) {
        message.append(" (user: ").append(authId).append(")");
      }

      String groupId = json.get("group_id");
      if (groupId != null && !groupId.isEmpty()) {
        message.append(" (group: ").append(groupId).append(")");
      }
    } catch (IOException e) {
      LOG.error("Failed parsing error response: " + e.getMessage());
    }

    return message.toString();
  }

  /**
   * Ask for a token.
   *
   * @see IDBClient#requestKnoxDelegationToken(KnoxSession, String, URI)
   */
  @Override
  public RequestDTResponseMessage requestKnoxDelegationToken(final KnoxSession knoxSession,
                                                             final String origin,
                                                             final URI fsUri)
      throws IOException {
    LOG.trace("Getting a new Knox Delegation Token");

    checkNotNull(knoxSession, "Missing KnoxSession");

    Get.Request getRequest = Token.get(knoxSession, proxyUser);
    CloudAccessBrokerTokenGet request = new CloudAccessBrokerTokenGet(getRequest);

    LOG.debug("Fetching IDB access token from {} (session origin {})", request.getRequestURI(), origin);
    try {
      BasicResponse response;

      if (hasKerberosCredentials()) {
        // CDPD-3149
        if (owner.isFromKeytab()) {
          owner.checkTGTAndReloginFromKeytab();
        } else {
          owner.reloginFromTicketCache();
        }
        response = owner.doAs((PrivilegedAction<BasicResponse>) () -> requestExecutor.execute(request));
      } else {
        response = requestExecutor.execute(request);
      }

      RequestDTResponseMessage struct = processGet(
          RequestDTResponseMessage.class,
          request.getRequestURI(),
          response);
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
    } catch (Throwable t) {
      LOG.error(t.toString(), t);
      throw new IOException(t.toString(), t);
    }
  }

  @Override
  public RequestDTResponseMessage updateDelegationToken(final KnoxToken knoxToken) throws Exception {
    return requestKnoxDelegationToken(createKnoxCABSession(knoxToken),
        knoxToken.getOrigin(),
        null);
  }


  /**
   * Decide what IDB method to use.
   *
   * @see IDBClient#determineIDBMethodToCall()
   */
  @Override
  public IDBMethod determineIDBMethodToCall() {
    IDBMethod method = IDBMethod.DEFAULT;
    if (onlyGroups) {
      method = IDBMethod.GROUPS_ONLY;
    }
    if (specificGroup != null) {
      method = IDBMethod.SPECIFIC_GROUP;
    }
    if (onlyUser) {
      method = IDBMethod.USER_ONLY;
    }
    if (specificRole != null) {
      method = IDBMethod.SPECIFIC_ROLE;
    }
    return method;
  }

  /**
   * Build a diagnostics string for including in error messages.
   *
   * @param uri  FS URI.
   * @param user User
   * @return a string for exceptions; includes user, token info
   */
  public static String buildDiagnosticsString(final URI uri,
                                              final UserGroupInformation user) {
    final StringBuilder diagnostics = new StringBuilder(32);
    diagnostics.append("filesystem =")
               .append(uri != null ? uri : "(null")
               .append("; owner=")
               .append(user != null ? user.getUserName() : "(null)")
               .append("; ");
    if (user != null) {
      diagnostics.append("tokens=[");
      Collection<org.apache.hadoop.security.token.Token<? extends TokenIdentifier>>
          tokens = user.getTokens();
      for (org.apache.hadoop.security.token.Token<? extends TokenIdentifier> token : tokens) {
        diagnostics.append(token.toString()).append(';');
      }
      diagnostics.append(']');
    }
    return diagnostics.toString();
  }

  @Override
  public String toString() {
    return "IDBClient{gateway=" + getGatewayAddress() + '}';
  }

  protected abstract boolean getOnlyUser(Configuration configuration);

  protected abstract boolean getOnlyGroups(Configuration configuration);

  protected abstract String getSpecificRole(Configuration configuration);

  protected abstract String getSpecificGroup(Configuration configuration);

  protected abstract String getTruststorePath(Configuration configuration);

  protected abstract char[] getTruststorePassword(Configuration configuration) throws IOException;

  protected abstract boolean getUseCertificateFromDT(Configuration configuration);

  protected abstract String getDelegationTokensURL(Configuration configuration);

  protected abstract String getCredentialsURL(Configuration configuration);

  protected abstract String getCredentialsType(Configuration configuration);

  protected abstract String[] getGatewayAddress(Configuration configuration);

  protected abstract String getUsername(Configuration configuration);

  protected abstract String getUsernamePropertyName();

  protected abstract String getPassword(Configuration configuration);

  protected abstract String getPasswordPropertyName();

  protected abstract boolean preferKnoxTokenOverKerberos(Configuration configuration);


  @Override
  public String getGatewayAddress() {
    return requestExecutor.getEndpoint();
  }

  protected String buildUrl(String baseUrl, String path) {
    StringBuilder url = new StringBuilder(maybeAddTrailingSlash(baseUrl));

    if (StringUtils.isNotEmpty(path)) {
      url.append(maybeRemoveLeadingSlash(path));
    }

    return url.toString();
  }

  /**
   * Translate an a Knox exception into an IOException, using HTTP error
   * codes if present.
   *
   * @param requestURI URI of the request.
   * @param extraDiags any extra text, or "".
   * @param e          exception
   * @return an exception to throw.
   */
  protected IOException translateException(URI requestURI,
                                           String extraDiags,
                                           KnoxShellException e) {
    String path = requestURI.toString();
    Throwable cause = e.getCause();
    IOException ioe;

    if (cause instanceof ErrorResponse) {
      ErrorResponse error = (ErrorResponse) cause;
      HttpResponse response = error.getResponse();
      int status = response.getStatusLine().getStatusCode();
      String message = String.format(Locale.ROOT, "Error %03d from %s", status, path);
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
          ioe = new IOException(message + "  " + e, e);
      }
    } else if (cause instanceof SSLHandshakeException) {
      ioe = new IOException(String.format(Locale.ROOT, "While connecting to %s: %s%s",
          path, e.toString(), (extraDiags.isEmpty() ? "" : (" (" + extraDiags + ")"))),
          e);
      LOG.error(ioe.toString());
    } else {
      // some other error message.
      String errorMessage = e.toString();
      if (errorMessage.contains(E_NO_PRINCIPAL)) {
        errorMessage += " - " + E_NO_KAUTH;
      }
      ioe = new IOException("From " + path
          + " " + errorMessage
          + (extraDiags.isEmpty() ? "" : (" " + extraDiags)),
          e);
    }
    return ioe;
  }

  /**
   * handle a GET response by validating headers and status,
   * parsing to the given type.
   *
   * @param <T>        final type
   * @param clazz      class of final type
   * @param requestURI URI of the request
   * @param response   GET response
   * @return an instant of the JSON-unmarshalled type
   * @throws IOException failure
   */
  protected <T> T processGet(final Class<T> clazz,
                             @Nullable final URI requestURI,
                             final BasicResponse response) throws IOException {

    int statusCode = response.getStatusCode();
    String type = response.getContentType();

    String dest = requestURI != null
        ? requestURI.toString()
        : ("path under " + getGatewayAddress());
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
          type, getGatewayAddress(), body);
    }

    JsonSerialization<T> serDeser = new JsonSerialization<>(clazz,
        false, true);
    InputStream stream = response.getStream();
    return serDeser.fromJsonStream(stream);
  }

  protected String getPropertyValue(Configuration configuration, IDBProperty property, boolean trimmed) {
    String value = (trimmed) ? configuration.getTrimmed(property.getPropertyName(), property.getDefaultValue())
                             : configuration.get(property.getPropertyName(), property.getDefaultValue());

    // In the case that the specified property is explicitly set to an empty value, it will be better to return
    // the default value instead
    if (value != null && value.isEmpty()) {
      value = property.getDefaultValue();
    }
    return value;
  }

  protected String getPropertyValue(Configuration configuration, IDBProperty property) {
    return getPropertyValue(configuration, property, true);
  }

  protected Boolean getPropertyValueAsBoolean(Configuration configuration, IDBProperty property) {
    return configuration.getBoolean(property.getPropertyName(), Boolean.valueOf(property.getDefaultValue()));
  }

  private static String maybeAddTrailingSlash(final String s) {
    return s.endsWith("/") ? s : (s + "/");
  }

  private static String maybeRemoveLeadingSlash(final String s) {
    return s.startsWith("/") ? s.substring(1) : s;
  }

  /**
   * Initialize the connection as a full IDB Client capable of talking
   * to IDBroker, authenticating with kerberos, and asking for new
   * credentials.
   *
   * @param configuration Configuration to use.
   * @throws IOException IO problems.
   */
  private void initializeAsFullIDBClient(final Configuration configuration, final UserGroupInformation owner) throws IOException {
    this.owner = owner;

    /*
     * Determine if a proxied user should be set in the request to get a Knox Delegation Token.
     */
    if (owner != null && UserGroupInformation.isSecurityEnabled()) {
      if (LOG.isDebugEnabled()) {
        UserGroupInformation.logAllUserInfo(LOG, this.owner);
      }

      UserGroupInformation realUser = this.owner.getRealUser();
      if (realUser != null) {
        proxyUser = this.owner.getShortUserName();
        this.owner = realUser;
      }
    }

    config = configuration;

    // Make sure the configuration includes externally-referenced SSL settings (e.g., AutoTLS)
    CommonUtils.ensureSSLClientConfigLoaded(config);

    // Initialize the request executor for this client
    String[] endpoints = getGatewayAddress(configuration);
    Preconditions.checkState((endpoints != null && endpoints.length > 0),
        "At least one CloudAccessBroker endpoint must be configured.");
    requestExecutor = new DefaultRequestExecutor(Arrays.asList(endpoints));

    if (LOG.isDebugEnabled()) {
      List<String> baseURLs = getGatewayBaseURLs();
      if (baseURLs.size() == 1) {
        LOG.debug("The configured IDBroker gateway is {}", baseURLs.get(0));
      } else {
        LOG.debug("The following IDBroker gateways have been configured, using {} (for now): \n\t{}",
            getGatewayAddress(), String.join("\n\t", baseURLs));
      }
    }

    LOG.debug("IDBroker credentials URL is {}", getCredentialsURL());
    LOG.debug("IDBroker Knox Tokens URL is {}", getIdbTokensURL());

    useCertificateFromDT = getUseCertificateFromDT(configuration);

    truststore = getTruststorePath(configuration);
    if ((truststore == null)) {
      truststore = configuration.getTrimmed(DEFAULT_PROPERTY_NAME_SSL_TRUSTSTORE_LOCATION);
    }
    LOG.debug("Trust store is {}",
        truststore != null ? truststore : ("unset -using default path"));
    if (truststore != null) {
      File f = new File(truststore);
      if (!f.exists()) {
        throw new FileNotFoundException("Truststore not found: " + f.getAbsolutePath());
      }
    }

    try {
      char[] trustPass = getTruststorePassword(configuration);
      if ((trustPass == null)) {
        trustPass = configuration.getPassword(DEFAULT_PROPERTY_NAME_SSL_TRUSTSTORE_PASS);
      }
      if (trustPass != null) {
        truststorePass = new String(trustPass);
      }
    } catch (IOException e) {
      LOG.debug("Problem with Configuration.getPassword()", e);
      truststorePass = IDBConstants.DEFAULT_CERTIFICATE_PASSWORD;
    }

    specificGroup = getSpecificGroup(configuration);
    specificRole = getSpecificRole(configuration);
    onlyGroups = getOnlyGroups(configuration);
    onlyUser = getOnlyUser(configuration);

    LOG.debug("Created client to {}", getGatewayAddress());
  }

// TODO: PJZ: Maybe move to EndpointManager ? Should be optional though, at least for testing
//  private String[] processGatewayAddresses(String gatewayAddress) {
//    HashSet<String> set = new HashSet<>();
//
//    if (StringUtils.isNotEmpty(gatewayAddress)) {
//      String[] urls = gatewayAddress.split("\\s*[,;]\\s*");
//
//      for (String url : urls) {
//        try {
//          URI uri = new URI(url);
//
//          String host = uri.getHost();
//          if (isEmpty(host)) {
//            LOG.warn("Missing host while processing Gateway addresses. Ignoring entry: {}", uri);
//          } else {
//            try {
//              InetAddress[] addresses = InetAddress.getAllByName(host);
//              if (LOG.isDebugEnabled()) {
//                LOG.debug("Address of IDBroker service {}", Arrays.toString(addresses));
//              }
//
//              // ###################################################################################
//              // If we get here, the URL is valid and should be included in the usable Gateway addresses
//              // ###################################################################################
//              set.add(url);
//
//            } catch (UnknownHostException e) {
//              LOG.warn("Unknown host, {}, in URL found while processing Gateway addresses. Ignoring entry: {}", host, url);
//            }
//          }
//        } catch (URISyntaxException e) {
//          LOG.warn("Invalid URI found while processing Gateway addresses. Ignoring entry: {}", url);
//        }
//      }
//    }
//
//    return set.toArray(new String[0]);
//  }

  /**
   * Check that the gateway is configured.
   * If it is not set, then this IDB client was not initialized
   * as a full client.
   */
  private void checkGatewayConfigured() {
    checkState(!StringUtils.isBlank(getGatewayAddress()), E_IDB_GATEWAY_UNDEFINED);
  }

  private CloudAccessBrokerSession createKnoxSession(final KnoxToken knoxToken,
                                                     final String endPointUrl,
                                                     final boolean useEndpointCertificate)
      throws IOException {

    checkNotNull(knoxToken, "Empty KnoxToken");

    return createKnoxSession(knoxToken.getAccessToken(),
        endPointUrl,
        knoxToken.getEndpointPublicCert(),
        useEndpointCertificate);
  }

  private CloudAccessBrokerSession createKnoxSession(final String delegationToken,
                                                     final String endPointUrl,
                                                     final String endpointCert,
                                                     final boolean useEndpointCertificate)
      throws IOException {
    return createKnoxSession(delegationToken, "Bearer", endPointUrl, endpointCert, useEndpointCertificate);
  }

  private CloudAccessBrokerSession createKnoxSession(final String delegationToken,
                                                     final String delegationTokenType,
                                                     final String endpointUrl,
                                                     final String endpointCert,
                                                     final boolean useEndpointCertificate)
      throws IOException {

    checkArgument(StringUtils.isNotEmpty(delegationToken), "Empty delegation token");

    checkArgument(StringUtils.isNotEmpty(endpointUrl), "Empty endpoint");

    if (LOG.isDebugEnabled()) {
      LOG.debug("Establishing Knox session with Cloud Access Broker at {}\n\tcert: {}{}",
          endpointUrl,
          (StringUtils.isEmpty(endpointCert)) ? "<N/A>" : endpointCert.substring(0, 4),
          (useEndpointCertificate) ? "" : " [disabled by request]");
    }

    ClientContext context = createKnoxClientContext(endpointUrl,
        endpointCert,
        useEndpointCertificate);

    try {
      CloudAccessBrokerSession session = CloudAccessBrokerSession.create(context);

      String type = delegationTokenType == null ? "Bearer" : delegationTokenType;
      session.setHeaders(Collections.singletonMap("Authorization", type + " " + delegationToken));

      return session;
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  private CloudAccessBrokerSession createKnoxCABSessionUsingKerberos() throws IOException {
    try {
      if (hasKerberosCredentials()) {
        return owner.doAs((PrivilegedExceptionAction<CloudAccessBrokerSession>) CloudAccessBrokerSession.create(createKnoxClientContext(getCredentialsURL(), true)));
      } else {
        return CloudAccessBrokerSession.create(createKnoxClientContext(getCredentialsURL(), true));
      }
    } catch (InterruptedException | URISyntaxException e) {
      throw new IOException(e);
    }
  }

  private ClientContext createKnoxClientContext(String endpointUrl, String username, String password) {
    return updateKnoxClientContext(ClientContext.with(username, password, endpointUrl), null, false, false);
  }

  private ClientContext createKnoxClientContext(String endpointUrl, boolean enableKerberos) {
    return updateKnoxClientContext(ClientContext.with(endpointUrl), null, false, enableKerberos);
  }

  private ClientContext createKnoxClientContext(String endpointUrl, String endpointCertificate, boolean useEndpointCertificate) {
    return updateKnoxClientContext(ClientContext.with(endpointUrl), endpointCertificate, useEndpointCertificate, false);
  }

  private ClientContext updateKnoxClientContext(ClientContext clientContext,
                                                String endpointCertificate,
                                                boolean useEndpointCertificate,
                                                boolean enableKerberos) {

    if (enableKerberos) {
      LOG.debug("Creating Knox client context enabling support for Kerberos");
      clientContext.kerberos()
                   .enable(true)
                   .debug(LOG.isDebugEnabled());
    }

    // If a truststore is set, use it...
    String trustStorePath = getTruststorePath();
    if (StringUtils.isNotEmpty(trustStorePath)) {
      LOG.debug("Creating Knox client context using the supplied truststore: {}", trustStorePath);
      clientContext.connection().withTruststore(trustStorePath, getTruststorePassword());
    }

    if (useEndpointCertificate && StringUtils.isNotEmpty(endpointCertificate)) {
      LOG.debug("Creating Knox client context using a supplied endpoint certificate");
      clientContext.connection().withPublicCertPem(endpointCertificate);
    }

    return clientContext;
  }

}

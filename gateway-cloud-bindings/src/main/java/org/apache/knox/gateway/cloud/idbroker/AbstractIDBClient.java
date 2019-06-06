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
import static org.apache.knox.gateway.cloud.idbroker.common.Preconditions.checkState;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.hadoop.util.JsonSerialization;
import org.apache.http.HttpResponse;
import org.apache.knox.gateway.cloud.idbroker.common.CommonUtils;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.net.ssl.SSLHandshakeException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.AccessDeniedException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
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

  private String origin;

  private UserGroupInformation owner;

  protected AbstractIDBClient(
      final Configuration configuration,
      final UserGroupInformation owner,
      final String origin) throws IOException {
    initializeAsFullIDBClient(configuration, owner);
    this.origin = origin;
  }

  /**
   * Create without any initialization.
   */
  protected AbstractIDBClient(final String origin) {
    this.origin = origin;
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
    return getCredentialsURL(config);
  }

  public String getIdbTokensURL() {
    return getDelegationTokensURL(config);
  }

  @Override
  public Pair<KnoxSession, String> login(Configuration configuration) throws IOException {
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
      LOG.debug("Authenticating with IDBroker via username and password");

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

      sessionOrigin = "local login credentials";
      session = knoxSessionFromSecrets(username, password);
    } else if (IDBConstants.HADOOP_AUTH_KERBEROS.equalsIgnoreCase(hadoopAuth)) {
      LOG.debug("Authenticating with IDBroker with Kerberos");
      sessionOrigin = "local kerberos login";
      try {
        session = owner.doAs((PrivilegedExceptionAction<KnoxSession>) this::knoxSessionFromKerberos);
      } catch (InterruptedException e) {
        throw (IOException) new InterruptedIOException(e.toString()).initCause(e);
      }
    } else {
      // no match on either option
      // Current;
      LOG.warn("Unknown IDBroker authentication mechanism: \"{}\"", hadoopAuth);
    }

    return Pair.of(session, sessionOrigin);
  }

  /**
   * @see IDBClient#cloudSessionFromDelegationToken(String, String)
   */
  @Override
  public CloudAccessBrokerSession cloudSessionFromDelegationToken(final String delegationToken,
                                                                  final String endpointCert)
      throws IOException {
    return createKnoxSession(delegationToken, endpointCert, useCertificateFromDT);
  }

  /**
   * @see IDBClient#cloudSessionFromDelegationToken(String, String, String)
   */
  @Override
  public CloudAccessBrokerSession cloudSessionFromDelegationToken(final String delegationToken,
                                                                  final String delegationTokenType,
                                                                  final String endpointCert)
      throws IOException {
    return createKnoxSession(delegationToken,
                             delegationTokenType,
                             endpointCert,
                             useCertificateFromDT);
  }

  /**
   * Create a Knox session from a username and password.
   *
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
    try {
      LOG.debug("Logging in to {} as {}", url, username);
      return CloudAccessBrokerSession.create(createKnoxClientContext(url, username, password));
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  /**
   * @see IDBClient#cloudSessionFromDT(String, String)
   */
  @Override
  public CloudAccessBrokerSession cloudSessionFromDT(String delegationToken,
                                                     final String endpointCert)
      throws IOException {
    checkGatewayConfigured();
    return createKnoxSession(delegationToken,
                             getCredentialsURL(),
                             endpointCert,
                             !endpointCert.isEmpty() && useCertificateFromDT);
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

    BasicResponse response = requestExecutor.execute(request);

    return extractCloudCredentialsFromResponse(response);
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

    boolean usingKerberos = (owner != null) && UserGroupInformation.isSecurityEnabled();

    /*
     * Determine if a proxied user should be set in the request to get a Knox Delegation Token.
     *
     * If Kerberos is being used for authentication and the current user and the owner/login user
     * are different, than the request needs to have a doAs user specified using the short
     * (translated) username from the current user's UGI instance.
     */
    UserGroupInformation currentUser = null;
    if (usingKerberos) {
      currentUser = UserGroupInformation.getCurrentUser();

      if (LOG.isDebugEnabled()) {
        UserGroupInformation.logAllUserInfo(LOG, currentUser);
      }
    }

    Get.Request getRequest;
    if ((currentUser != null) && !currentUser.getShortUserName().equalsIgnoreCase(owner.getShortUserName())) {
      getRequest = Token.get(knoxSession, currentUser.getShortUserName());
    } else {
      getRequest = Token.get(knoxSession);
    }

    CloudAccessBrokerTokenGet request = new CloudAccessBrokerTokenGet(getRequest);

    LOG.debug("Fetching IDB access token from {} (session origin {})", request.getRequestURI(), origin);
    try {
      BasicResponse response;

      if (usingKerberos) {
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
  public RequestDTResponseMessage updateDelegationToken(String delegationToken,
                                                        String delegationTokenType,
                                                        String cabPublicCert) throws Exception {
    return requestKnoxDelegationToken(cloudSessionFromDelegationToken(delegationToken,
                                                                      delegationTokenType,
                                                                      cabPublicCert),
                                      origin,
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
    if (specificGroup != null) {
      method = IDBMethod.SPECIFIC_GROUP;
    }
    if (specificRole != null) {
      method = IDBMethod.SPECIFIC_ROLE;
    }
    if (onlyUser) {
      method = IDBMethod.USER_ONLY;
    }
    if (onlyGroups) {
      method = IDBMethod.GROUPS_ONLY;
    }
    return method;
  }

  /**
   * Create a session bonded to the knox DT URL via Kerberos auth.
   *
   * @return the session
   * @throws IOException failure
   */
  public KnoxSession knoxSessionFromKerberos() throws IOException {
    checkGatewayConfigured();
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
   * Build a diagnostics string for including in error messages.
   *
   * @param uri  FS URI.
   * @param user User
   * @return a string for exceptions; includes user, token info
   */
  public static String buildDiagnosticsString(final URI uri,
                                              final UserGroupInformation user) {
    final StringBuilder diagnostics = new StringBuilder();
    diagnostics.append("filesystem =")
               .append(uri != null ? uri : "(null")
               .append("; ")
               .append("owner=")
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

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("IDBClient{");
    sb.append("gateway='")
      .append(getGatewayAddress())
      .append('\'')
      .append("origin='").append(origin)
      .append('\'')
      .append('}');
    return sb.toString();
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
          ioe = new IOException(message + "  " + e, e);
      }
    } else if (cause instanceof SSLHandshakeException) {
      ioe = new IOException(String.format("While connecting to %s: %s%s",
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
    return (trimmed)
        ? configuration.getTrimmed(property.getPropertyName(), property.getDefaultValue())
        : configuration.get(property.getPropertyName(), property.getDefaultValue());
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

    config = configuration;

    // Make sure the configuration includes externally-referenced SSL settings (e.g., AutoTLS)
    CommonUtils.ensureSSLClientConfigLoaded(config);

    // Initialize the request executor for this client
    String[] endpoints = getGatewayAddress(configuration);
    Preconditions.checkState((endpoints != null && endpoints.length > 0),
                             "At least one CloudAccessBroker endpoint must be configured.");
    requestExecutor = new DefaultRequestExecutor(Arrays.asList(endpoints));

    checkGatewayConfigured();

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

  private CloudAccessBrokerSession createKnoxSession(final String delegationToken,
                                                     final String endpointCert,
                                                     final boolean useEndpointCertificate)
      throws IOException {
    return createKnoxSession(delegationToken, "Bearer", endpointCert, useEndpointCertificate);
  }

  private CloudAccessBrokerSession createKnoxSession(final String delegationToken,
                                                     final String delegationTokenType,
                                                     final String endpointCert,
                                                     final boolean useEndpointCertificate)
      throws IOException {

    checkArgument(StringUtils.isNotEmpty(delegationToken), "Empty delegation token");

    String endpoint = getCredentialsURL();
    checkArgument(StringUtils.isNotEmpty(endpoint), "Empty endpoint");

    LOG.debug("Establishing Knox session with Cloud Access Broker at {}\n\tcert: {}{}",
              endpoint,
              (StringUtils.isEmpty(endpointCert)) ? "<N/A>" : endpointCert.substring(0, 4),
              (useEndpointCertificate) ? "" : " [disabled by request]");

    Map<String, String> headers = new HashMap<>();
    String type = delegationTokenType == null ? "Bearer" : delegationTokenType;
    headers.put("Authorization", type + " " + delegationToken);

    try {
      LOG.debug("Logging in to {}", endpoint);
      CloudAccessBrokerSession session =
          CloudAccessBrokerSession.create(createKnoxClientContext(endpoint,
                                                                  endpointCert,
                                                                  useEndpointCertificate));
      session.setHeaders(headers);
      return session;
    } catch (URISyntaxException e) {
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
      clientContext.withSubjectCredsOnly(true)
                   .kerberos()
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

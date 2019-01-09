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
import java.nio.file.AccessDeniedException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.DelegationTokenIOException;
import org.apache.hadoop.fs.s3a.commit.DurationInfo;
import org.apache.hadoop.util.JsonSerialization;
import org.apache.knox.gateway.cloud.idbroker.messages.AuthResponseAWSMessage;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.cloud.idbroker.messages.ValidationFailure;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.HadoopException;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.idbroker.Credentials;
import org.apache.knox.gateway.shell.knox.token.Get;
import org.apache.knox.gateway.shell.knox.token.Token;

import static com.google.common.base.Preconditions.checkArgument;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.*;

/**
 * This class tries to wrap up all the operations which the DT client
 * will do, so that they can be tested on their own, and to merge
 * common code, such as the validation of HTTP responses.
 */
public class IDBClient implements IdentityBrokerClient {

  protected static final Logger LOG =
      LoggerFactory.getLogger(IDBClient.class);

  private String gateway;

  private String truststore;

  private String truststorePass;
  private String dtURL;
  private String awsURL;

  private String specificGroup;
  private String specificRole;
  private String onlyUser;
  private String onlyGroups;

  /**
   * Create.
   * 
   * @param conf Configuration to drive off.
   * @throws IOException IE problems.
   */
  public IDBClient(Configuration conf) throws IOException {
	  init(conf);
  }

  /**
   * Initialize.
   * @param conf Configuration to drive off.
   * @throws IOException IE problems.
   */
  public void init(Configuration conf) throws IOException {
    this.gateway = maybeAddTrailingSlash(
        conf.get(IDBROKER_GATEWAY,
            IDBROKER_GATEWAY_DEFAULT));
    // quick sanity check , is that a URL with a resolvable hostname.
    if (gateway.isEmpty()) {
      throw new DelegationTokenIOException(
          "No gateway defined in " + IDBROKER_GATEWAY);
    }
    try {
      String host = new URI(gateway).getHost();
      InetAddress.getAllByName(host);
    } catch (URISyntaxException e) {
      throw new DelegationTokenIOException("Not a valid URI: " + gateway, e);
    }
    String aws = conf.get(IDBROKER_AWS_PATH,
        IDBROKER_AWS_PATH_DEFAULT);
    this.awsURL = gateway + aws;
    
    String dt = conf.get(IDBROKER_DT_PATH,
        IDBROKER_DT_PATH_DEFAULT);
    this.dtURL = gateway + dt;

    truststore = conf.get(IDBROKER_TRUSTSTORE_LOCATION,
        DEFAULT_CERTIFICATE_PATH);
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

  public String getGateway() {
    return gateway;
  }

  public String getTruststorePath() {
    return truststore;
  }

  public String getTruststorePass() {
    return truststorePass;
  }

  public String cloudURL() {
    return awsURL;
  }

  public String dtURL() {
    return dtURL;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("IDBClient{");
    sb.append("gateway='").append(gateway).append('\'');
    sb.append('}');
    return sb.toString();
  }

  /**
   * Build some AWS credentials from the response.
   * @param responseAWSStruct parsed JSON response
   * @return the AWS credentials
   * @throws IOException failure
   */
  @Override
public MarshalledCredentials fromResponse(
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
   * @see org.apache.knox.gateway.cloud.idbroker.IdentityBrokerClient#cloudSessionFromDT(java.lang.String)
   */
  @Override
  public KnoxSession cloudSessionFromDT(String delegationToken)
      throws IOException {
    checkArgument(StringUtils.isNotEmpty(delegationToken),
        "Empty delegation Token");
    // build up the headers
    final HashMap<String, String> headers = new HashMap<>();
    headers.put("Authorization", "Bearer " + delegationToken);
    return cloudSession(headers);
  }

  /**
   * Create the knoxsession.
   * @param headers
   * @return the new session.
   * @see org.apache.knox.gateway.cloud.idbroker.IdentityBrokerClient#cloudSession(java.util.HashMap)
   * @throws IOException
   */
  @Override
  public KnoxSession cloudSession(Map<String, String> headers)
      throws IOException {
    String url = cloudURL();
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Logging in to %s", url)) {
      return KnoxSession.login(url, headers);
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  /**
   * Create a session bonded to the knox DT URL.
   * @param username username
   * @param password pass
   * @return the session
   * @throws IOException failure
   */
  public KnoxSession knoxDtSession(String username, String password)
      throws IOException {
    if (StringUtils.isEmpty(username)) {
      throw new AccessDeniedException("No IDBroker Username");
    }

    String url = dtURL();
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Logging in to %s as %s", url, username)) {
      return KnoxSession.login(url, username, password);
    } catch (URISyntaxException e) {
      throw new IOException(e);
    }
  }

  /**
   * Create a session bonded to the knox DT URL via Kerberos authn.
   * @return the session
   * @throws IOException failure
   */
  public KnoxSession knoxDtSession()
      throws IOException {
    String url = dtURL();
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Logging in to %s", url)) {
      return KnoxSession.kerberosLogin(url);
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
      return fromResponse(
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
   * @see org.apache.knox.gateway.cloud.idbroker.IdentityBrokerClient#requestKnoxDelegationToken(org.apache.knox.gateway.shell.KnoxSession)
   */
  @Override
  public RequestDTResponseMessage requestKnoxDelegationToken(KnoxSession dtSession)
      throws IOException {
    Get.Request request = Token.get(dtSession);
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Fetching IDB access token from %s", request.getRequestURI())) {
      try {

        RequestDTResponseMessage struct = processGet(
            RequestDTResponseMessage.class,
            request.getRequestURI(),
            request.now());
        String access_token = struct.access_token;
        ValidationFailure.verify(StringUtils.isNotEmpty(access_token),
            "No access token from DT login");
        return struct;
      } catch (HadoopException e) {
        // add the URL
        throw new DelegationTokenIOException("From " + gateway
            + " " + e.toString(), e);
      }
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
  
  public static String expiryDate(long expiryTime) {
    return new Date(TimeUnit.SECONDS.toMillis(expiryTime)).toString();
  }
}

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

package org.apache.knox.gateway.cloud.idbroker.s3a;

import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_ONLY_GROUPS_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_ONLY_USER_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_PATH;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_SPECIFIC_GROUP_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_SPECIFIC_ROLE_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_USE_DT_CERT;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.S3AUtils;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.DelegationTokenIOException;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.http.HttpResponse;
import org.apache.knox.gateway.cloud.idbroker.AbstractIDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.DefaultEndpointManager;
import org.apache.knox.gateway.cloud.idbroker.common.DefaultRequestExecutor;
import org.apache.knox.gateway.cloud.idbroker.common.EndpointManager;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.AccessDeniedException;
import java.util.Arrays;
import java.util.Locale;

public class S3AIDBClient extends AbstractIDBClient<MarshalledCredentials> {

  private static final Logger LOG = LoggerFactory.getLogger(S3AIDBClient.class);

  private final S3AFileSystem fs;

  /**
   * Create a full IDB Client, configured to be able to talk to
   * the gateway to request new IDB tokens.
   *
   * @param conf  Configuration to use.
   * @param owner owner of the client.
   * @return a new instance.
   * @throws IOException IO problems.
   */
  public static S3AIDBClient createFullIDBClient(
      final Configuration conf,
      final UserGroupInformation owner,
      S3AFileSystem fs)
      throws IOException {
    return new S3AIDBClient(conf, owner, fs);
  }

  /**
   * Create a light IDB Client, only able to talk to CAB endpoints
   * with information coming from the parsed DTs themselves.
   *
   * @param conf Configuration to use.
   * @return a new instance.
   * @throws IOException IO problems.
   */
  public static S3AIDBClient createLightIDBClient(Configuration conf, S3AFileSystem fs)
      throws IOException {
    S3AIDBClient client = new S3AIDBClient(conf, null, fs);
    EndpointManager em =
        new DefaultEndpointManager(Arrays.asList(conf.get(IDBROKER_GATEWAY.getPropertyName(),
                                                          IDBROKER_GATEWAY.getDefaultValue())));
    client.requestExecutor = new DefaultRequestExecutor(em);
    return client;
  }

  S3AIDBClient(Configuration conf, UserGroupInformation owner, S3AFileSystem fs) throws IOException {
    super(conf, owner);
    this.fs = fs;
  }

  @Override
  protected boolean getOnlyUser(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, IDBROKER_ONLY_USER_METHOD);
  }

  @Override
  protected boolean getOnlyGroups(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, IDBROKER_ONLY_GROUPS_METHOD);
  }

  @Override
  protected String getSpecificRole(Configuration configuration) {
    return getPropertyValue(configuration, IDBROKER_SPECIFIC_ROLE_METHOD);
  }

  @Override
  protected String getSpecificGroup(Configuration configuration) {
    return getPropertyValue(configuration, IDBROKER_SPECIFIC_GROUP_METHOD);
  }

  @Override
  protected String getTruststorePath(Configuration configuration) {
    return getPropertyValue(configuration, IDBROKER_TRUSTSTORE_LOCATION);
  }

  @Override
  protected boolean getUseCertificateFromDT(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, IDBROKER_USE_DT_CERT);
  }

  @Override
  protected char[] getTruststorePassword(Configuration configuration) throws IOException {
    char[] password = configuration.getPassword(IDBROKER_TRUSTSTORE_PASS.getPropertyName());
    if (password == null) {
      password = configuration.getPassword(IDBROKER_TRUSTSTORE_PASSWORD.getPropertyName());
    }
    return password;
  }

  @Override
  protected String getDelegationTokensURL(Configuration configuration) {
    return buildUrl(getGatewayAddress(),
                    getPropertyValue(configuration, IDBROKER_DT_PATH));
  }

  @Override
  protected String getCredentialsURL(Configuration configuration) {
    return buildUrl(getGatewayAddress(),
                    getPropertyValue(configuration, IDBROKER_PATH));
  }

  @Override
  protected String getCredentialsType(Configuration configuration) {
    return getPropertyValue(configuration, IDBROKER_CREDENTIALS_TYPE);
  }

  @Override
  protected String[] getGatewayAddress(Configuration configuration) {
    return configuration.getStrings(IDBROKER_GATEWAY.getPropertyName(), IDBROKER_GATEWAY.getDefaultValue());
  }

  @Override
  protected String getUsername(Configuration conf) {
    try {
      return S3AUtils.lookupPassword(fs.getBucket(), conf, IDBROKER_USERNAME.getPropertyName());
    } catch (IOException e) {
      LOG.warn("Failed to get the username from S3A, falling back to the configuration", e);
      return getPropertyValue(conf, IDBROKER_USERNAME);
    }

  }

  @Override
  protected String getUsernamePropertyName() {
    return IDBROKER_USERNAME.getPropertyName();
  }

  @Override
  protected String getPassword(Configuration conf) {
    try {
      return S3AUtils.lookupPassword(fs.getBucket(), conf, IDBROKER_PASSWORD.getPropertyName());
    } catch (IOException e) {
      LOG.warn("Failed to get the password from S3A, falling back to the configuration", e);
      return getPropertyValue(conf, IDBROKER_PASSWORD);
    }
  }

  @Override
  protected String getPasswordPropertyName() {
    return IDBROKER_PASSWORD.getPropertyName();
  }

  /**
   * Build some AWS credentials from the Knox AWS endpoint's response.
   *
   * @param basicResponse the response to parse
   * @return the AWS credentials
   * @throws IOException failure
   */
  @Override
  public MarshalledCredentials extractCloudCredentialsFromResponse(BasicResponse basicResponse)
      throws IOException {

    return responseToMarshalledCredentials(processGet(AuthResponseAWSMessage.class, null, basicResponse));
  }

  @Override
  protected IOException translateException(
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
          ioe = new DelegationTokenIOException(message + "  " + e, e);
      }
    } else {
      // some other error message.
      String errorMessage = e.toString();
      if (errorMessage.contains(E_NO_PRINCIPAL)) {
        errorMessage += " - " + E_NO_KAUTH;
      }
      ioe = new DelegationTokenIOException("From " + path
          + " " + errorMessage
          + (extraDiags.isEmpty() ? "" : (" " + extraDiags)),
          e);
    }
    return ioe;
  }

  MarshalledCredentials responseToMarshalledCredentials(AuthResponseAWSMessage responseAWSMessage) throws IOException {
    AuthResponseAWSMessage.CredentialsStruct responseCreds = responseAWSMessage.Credentials;
    final MarshalledCredentials received =
        new MarshalledCredentials(
            responseCreds.AccessKeyId,
            responseCreds.SecretAccessKey,
            responseCreds.SessionToken);
    received.setExpiration(responseCreds.Expiration);
    received.setRoleARN(responseAWSMessage.AssumedRoleUser.Arn);
    received.validate(getGatewayAddress() + " ",
        MarshalledCredentials.CredentialTypeRequired.SessionOnly);
    return received;
  }
}

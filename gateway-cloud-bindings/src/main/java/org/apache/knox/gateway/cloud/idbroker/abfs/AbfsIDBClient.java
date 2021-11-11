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

package org.apache.knox.gateway.cloud.idbroker.abfs;

import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_ENABLE_TOKEN_MONITOR;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_FAILOVER_SLEEP;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_HTTP_CONNECTION_REQ_TIMEOUT;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_HTTP_CONNECTION_TIMEOUT;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_HTTP_SOCKET_TIMEOUT;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_MAX_FAILOVER_ATTEMPTS;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_MAX_RETRY_ATTEMPTS;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_ONLY_GROUPS_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_ONLY_USER_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_PATH;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_PREFER_KNOX_TOKEN_OVER_KERBEROS;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_RETRY_SLEEP;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_SPECIFIC_GROUP_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_SPECIFIC_ROLE_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TOKEN_CLIENT_EXCLUSIONS;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_USE_DT_CERT;


import java.io.IOException;
import java.util.Collection;
import java.util.Date;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.oauth2.AzureADToken;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.StringUtils;
import org.apache.http.client.config.RequestConfig;
import org.apache.knox.gateway.cloud.idbroker.AbstractIDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.RequestErrorHandlingAttributes;
import org.apache.knox.gateway.shell.BasicResponse;

/**
 * AbfsIDBClient is an {@link AbstractIDBClient} implementation that obtains access tokens for Azure
 * Blob Storage File System driver.  This is used to connect the Azure Data Lake Gen2 file system.
 */
public class AbfsIDBClient extends AbstractIDBClient<AzureADToken> {

  /**
   * Create an IDB Client, configured to be able to talk to the gateway to request new IDB tokens.
   *
   * @param conf  Configuration to use.
   * @param owner owner of the client.
   * @throws IOException IO problems.
   */
  AbfsIDBClient(Configuration conf, UserGroupInformation owner) throws IOException {
    super(conf, owner);
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
  protected char[] getTruststorePassword(Configuration configuration) throws IOException {
    char[] password = configuration.getPassword(IDBROKER_TRUSTSTORE_PASS.getPropertyName());
    if (password == null) {
      password = configuration.getPassword(IDBROKER_TRUSTSTORE_PASSWORD.getPropertyName());
    }
    return password;
  }

  @Override
  protected boolean getUseCertificateFromDT(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, IDBROKER_USE_DT_CERT);
  }

  @Override
  protected String getDelegationTokensURL(Configuration configuration) {
    return buildUrl(getGatewayAddress(), getPropertyValue(configuration, IDBROKER_DT_PATH));
  }

  @Override
  protected String getCredentialsURL(Configuration configuration) {
    return buildUrl(getGatewayAddress(), getPropertyValue(configuration, IDBROKER_PATH));
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
    return getPropertyValue(conf, IDBROKER_USERNAME);
  }

  @Override
  protected String getUsernamePropertyName() {
    return IDBROKER_USERNAME.getPropertyName();
  }

  @Override
  protected String getPassword(Configuration conf) {
    return getPropertyValue(conf, IDBROKER_PASSWORD);
  }

  @Override
  protected String getPasswordPropertyName() {
    return IDBROKER_PASSWORD.getPropertyName();
  }

  @Override
  protected boolean preferKnoxTokenOverKerberos(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, IDBROKER_PREFER_KNOX_TOKEN_OVER_KERBEROS);
  }

  @Override
  protected Collection<String> getTokenClientExclusions(Configuration configuration) {
    final Collection<String> tokenClientExclusions = configuration.getTrimmedStringCollection(IDBROKER_TOKEN_CLIENT_EXCLUSIONS.getPropertyName());
    return tokenClientExclusions.isEmpty() ?  StringUtils.getTrimmedStringCollection(IDBROKER_TOKEN_CLIENT_EXCLUSIONS.getDefaultValue()) : tokenClientExclusions;
  }

  @Override
  protected boolean isTokenMonitorConfigured(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, IDBROKER_ENABLE_TOKEN_MONITOR);
  }

  @Override
  protected RequestErrorHandlingAttributes getRequestErrorHandlingAttributes(Configuration configuration) {
    return new RequestErrorHandlingAttributes(getPropertyValueAsInteger(IDBROKER_MAX_FAILOVER_ATTEMPTS), getPropertyValueAsInteger(IDBROKER_FAILOVER_SLEEP),
        getPropertyValueAsInteger(IDBROKER_MAX_RETRY_ATTEMPTS), getPropertyValueAsInteger(IDBROKER_RETRY_SLEEP));
  }

  @Override
  protected RequestConfig getHttpRequestConfiguration(Configuration configuration) {
    return RequestConfig.custom()
        .setConnectionRequestTimeout(getPropertyValueAsInteger(IDBROKER_HTTP_CONNECTION_REQ_TIMEOUT))
        .setConnectTimeout(getPropertyValueAsInteger(IDBROKER_HTTP_CONNECTION_TIMEOUT))
        .setSocketTimeout(getPropertyValueAsInteger(IDBROKER_HTTP_SOCKET_TIMEOUT))
        .build();
  }

  /**
   * Build some Azure credentials from the Knox response.
   *
   * @param basicResponse the response to parse
   * @return the Azure credentials
   * @throws IOException failure
   */
  @Override
  public AzureADToken extractCloudCredentialsFromResponse(BasicResponse basicResponse)
      throws IOException {

    AbfsAuthResponseMessage response = processGet(AbfsAuthResponseMessage.class, null, basicResponse);
    AzureADToken token = new AzureADToken();
    token.setAccessToken(response.getAccessToken());
    token.setExpiry(Date.from(response.getExpiry()));
    return token;
  }
}

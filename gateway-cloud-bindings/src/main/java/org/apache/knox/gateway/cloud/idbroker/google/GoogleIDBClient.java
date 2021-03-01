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

import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_ENABLE_TOKEN_MONITOR;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_FAILOVER_SLEEP;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_MAX_FAILOVER_ATTEMPTS;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_MAX_RETRY_ATTEMPTS;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_RETRY_SLEEP;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.cloud.idbroker.AbstractIDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.RequestErrorHandlingAttributes;
import org.apache.knox.gateway.shell.BasicResponse;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.hadoop.util.AccessTokenProvider;


public class GoogleIDBClient extends AbstractIDBClient<AccessTokenProvider.AccessToken> {

  public GoogleIDBClient(Configuration config, UserGroupInformation owner)
      throws IOException {
    super(config, owner);
  }

  @Override
  protected boolean getOnlyUser(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, GoogleIDBProperty.IDBROKER_ONLY_USER_METHOD);
  }

  @Override
  protected boolean getOnlyGroups(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, GoogleIDBProperty.IDBROKER_ONLY_GROUPS_METHOD);
  }

  @Override
  protected String getSpecificRole(Configuration configuration) {
    return getPropertyValue(configuration, GoogleIDBProperty.IDBROKER_SPECIFIC_ROLE_METHOD);
  }

  @Override
  protected String getSpecificGroup(Configuration configuration) {
    return getPropertyValue(configuration, GoogleIDBProperty.IDBROKER_SPECIFIC_GROUP_METHOD);
  }

  @Override
  protected String getTruststorePath(Configuration configuration) {
    return getPropertyValue(configuration, GoogleIDBProperty.IDBROKER_TRUSTSTORE_LOCATION);
  }

  @Override
  protected char[] getTruststorePassword(Configuration configuration) throws IOException {
    char[] password = configuration.getPassword(GoogleIDBProperty.IDBROKER_TRUSTSTORE_PASS.getPropertyName());
    if (password == null) {
      password = configuration.getPassword(GoogleIDBProperty.IDBROKER_TRUSTSTORE_PASSWORD.getPropertyName());
    }
    return password;
  }

  @Override
  protected boolean getUseCertificateFromDT(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, GoogleIDBProperty.IDBROKER_USE_DT_CERT);
  }

  @Override
  protected String getDelegationTokensURL(Configuration configuration) {
    return buildUrl(getGatewayAddress(),
                    getPropertyValue(configuration, GoogleIDBProperty.IDBROKER_DT_PATH));
  }

  @Override
  protected String getCredentialsURL(Configuration configuration) {
    return buildUrl(getGatewayAddress(),
                    getPropertyValue(configuration, GoogleIDBProperty.IDBROKER_PATH));
  }

  @Override
  protected String getCredentialsType(Configuration configuration) {
    return getPropertyValue(configuration, GoogleIDBProperty.IDBROKER_CREDENTIALS_TYPE);
  }

  @Override
  protected String[] getGatewayAddress(Configuration configuration) {
    return configuration.getStrings(IDBROKER_GATEWAY.getPropertyName(), IDBROKER_GATEWAY.getDefaultValue());
  }

  @Override
  protected String getUsername(Configuration configuration) {
    return getPropertyValue(configuration, GoogleIDBProperty.IDBROKER_USERNAME);
  }

  @Override
  protected String getUsernamePropertyName() {
    return GoogleIDBProperty.IDBROKER_USERNAME.getPropertyName();
  }

  @Override
  protected String getPassword(Configuration configuration) {
    return CABUtils.getConfigSecret(configuration,
                                    getPasswordPropertyName(),
                                    CloudAccessBrokerBindingConstants.DT_PASS_ENV_VAR);
  }

  @Override
  protected String getPasswordPropertyName() {
    return GoogleIDBProperty.IDBROKER_PASSWORD.getPropertyName();
  }

  @Override
  protected boolean preferKnoxTokenOverKerberos(Configuration configuration) {
    return getPropertyValueAsBoolean(configuration, GoogleIDBProperty.IDBROKER_PREFER_KNOX_TOKEN_OVER_KERBEROS);
  }

  @Override
  protected Collection<String> getTokenClientExclusions(Configuration configuration) {
    final Collection<String> tokenClientExclusions = configuration.getTrimmedStringCollection(GoogleIDBProperty.IDBROKER_TOKEN_CLIENT_EXCLUSIONS.getPropertyName());
    return tokenClientExclusions.isEmpty() ?  StringUtils.getTrimmedStringCollection(GoogleIDBProperty.IDBROKER_TOKEN_CLIENT_EXCLUSIONS.getDefaultValue()) : tokenClientExclusions;
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
  public AccessTokenProvider.AccessToken extractCloudCredentialsFromResponse(BasicResponse response) throws IOException {
    AccessTokenProvider.AccessToken token = null;

    if (response.getStatusCode() == HttpStatus.SC_OK) {
      if (response.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(response.getContentType())) {
          Map<String, Object> json = parseJSONResponse(response.getString());
          String accessToken = (String) json.get("accessToken");
          String expireTime = (String) json.get("expireTime");
          long expirationDateTime = DateTime.parseRfc3339(expireTime).getValue();
          token = new AccessTokenProvider.AccessToken(accessToken, expirationDateTime);
        }
      }
    }

    return token;
  }


  Map<String, Object> parseJSONResponse(final String response) throws IOException {
    ObjectMapper om = new ObjectMapper();
    return om.readValue(response, new TypeReference<Map<String, Object>>(){});
  }

}

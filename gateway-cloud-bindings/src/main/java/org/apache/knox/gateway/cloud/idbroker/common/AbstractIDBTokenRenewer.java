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
package org.apache.knox.gateway.cloud.idbroker.common;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.hadoop.security.token.TokenRenewer;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.apache.knox.gateway.shell.KnoxSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.Locale;
import java.util.Map;

/**
 * Base class for IDBroker delegation token renewer implementations.
 */
public abstract class AbstractIDBTokenRenewer extends TokenRenewer {

  private static final String ENDPOINT_TOKEN_API_PATH = "knoxtoken/api/v1/token";
  private static final String RENEW_ENDPOINT_PATH     = ENDPOINT_TOKEN_API_PATH + "/renew";
  private static final String CANCEL_ENDPOINT_PATH    = ENDPOINT_TOKEN_API_PATH + "/revoke";

  private static final Logger LOG = LoggerFactory.getLogger(AbstractIDBTokenRenewer.class);

  private static final String ERR_INVALID_RENEWER =
                        "The user (%s) does not match the renewer declared for the token: %s";

  @Override
  public boolean isManaged(Token<?> token) throws IOException {
    return handleKind(token.getKind()); // These tokens can be renewed and canceled
  }

  @Override
  public long renew(Token<?> token, Configuration configuration) throws IOException, InterruptedException {
    long result = 0;

    LOG.debug("Renew token");

    TokenIdentifier identifier = token.decodeIdentifier();
    if (handleKind(identifier.getKind())) {
      DelegationTokenIdentifier dtIdentifier = (DelegationTokenIdentifier) identifier;
      LOG.debug("Token: " + dtIdentifier.toString());

      UserGroupInformation user = UserGroupInformation.getCurrentUser();
      if (validateRenewer(user, dtIdentifier)) {

        String accessToken = getAccessToken(dtIdentifier);
        LOG.debug("Access token: " + accessToken);

        String renewalEndpoint = getRenewalEndpoint(configuration);
        LOG.debug("Renewal endpoint: " + renewalEndpoint);

        try {
          // Request that the token be renewed
          HttpResponse response = executeRequest(renewalEndpoint, accessToken, user);

          HttpEntity responseEntity = response.getEntity();
          if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
            if (responseEntity != null) {
              if (responseEntity.getContentLength() > 0) {
                if (MediaType.APPLICATION_JSON.equals(responseEntity.getContentType().getValue())) {
                  Map<String, Object> json = parseJSONResponse(EntityUtils.toString(responseEntity));
                  boolean isRenewed = Boolean.valueOf((String) json.getOrDefault("renewed", "false"));
                  if (isRenewed) {
                    LOG.debug("Token renewed.");
                    String expirationValue = (String) json.get("expires");
                    if (expirationValue != null && !expirationValue.isEmpty()) {
                      result = Long.parseLong(expirationValue);
                    }
                  } else {
                    LOG.error("Token could not be renewed: " + json.get("error"));
                  }
                }
              }
            }
          } else {
            LOG.error("Failed to renew token: " + response.getStatusLine().toString());
            if (responseEntity != null) {
              LOG.debug(EntityUtils.toString(responseEntity));
            }
          }
        } catch (Exception e) {
          LOG.error("Error renewing token: " + e.getMessage());
        }
      }
    }

    LOG.debug("Updated token expiration: " + result);
    return result;
  }

  @Override
  public void cancel(Token<?> token, Configuration configuration) throws IOException, InterruptedException {
    LOG.debug("Cancel token");

    TokenIdentifier identifier = token.decodeIdentifier();
    if (handleKind(identifier.getKind())) {
      DelegationTokenIdentifier dtIdentifier = (DelegationTokenIdentifier) identifier;
      LOG.debug("Token: " + dtIdentifier.toString());

      UserGroupInformation user = UserGroupInformation.getCurrentUser();
      if (validateRenewer(user, dtIdentifier)) {

        String accessToken = getAccessToken(dtIdentifier);
        LOG.debug("Access token: " + accessToken);

        String cancelEndpoint = getCancelEndpoint(configuration);
        LOG.debug("Cancellation endpoint: " + cancelEndpoint);

        try {
          // Request that the token be cancelled
          HttpResponse response = executeRequest(cancelEndpoint, accessToken, user);

          HttpEntity responseEntity = response.getEntity();
          if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
            if (responseEntity.getContentLength() > 0) {
              if (MediaType.APPLICATION_JSON.equals(responseEntity.getContentType().getValue())) {
                Map<String, Object> json = parseJSONResponse(EntityUtils.toString(responseEntity));
                boolean isCanceled = Boolean.valueOf((String) json.getOrDefault("revoked", "false"));
                if (isCanceled) {
                  LOG.debug("Token canceled.");
                } else {
                  LOG.error("Token could not be canceled: " + json.get("error"));
                }
              }
            }
          } else {
            LOG.error("Failed to cancel token: " + response.getStatusLine().toString());
            if (responseEntity != null) {
              LOG.debug(EntityUtils.toString(responseEntity));
            }
          }
        } catch (Exception e) {
          LOG.error("Error cancelling token: " + e.getMessage());
        }
      }
    }
  }

  /**
   * @return The value of the configuration property that specifies the IDBroker endpoint, which is the base for the
   *         delegation token endpoint.
   */
  protected abstract String getGatewayAddressConfigProperty(Configuration config);

  /**
   * @return The value of the configuration property that specifies the delegation token endpoint path.
   */
  protected abstract String getDelegationTokenPathConfigProperty(Configuration config);

  /**
   * @param identifier A token identifier.
   * @return The identifier-specific access token that is the IDBroker token.
   */
  protected abstract String getAccessToken(DelegationTokenIdentifier identifier);

  /**
   * @param config The Configuration
   * @return The endpoint which can be used for token renewal requests.
   */
  private String getRenewalEndpoint(Configuration config) {
    String endpoint = getTokenEndpoint(config);
    return (endpoint + RENEW_ENDPOINT_PATH);
  }

  /**
   * @param config The Configuration
   * @return The endpoint which can be used for token cancellation requests.
   */
  private String getCancelEndpoint(Configuration config) {
    String endpoint = getTokenEndpoint(config);
    return (endpoint + CANCEL_ENDPOINT_PATH);
  }

  /**
   * @param config The Configuration
   * @return The base endpoint token lifecycle requests.
   */
  private String getTokenEndpoint(Configuration config) {
    String gateway = getGatewayAddressConfigProperty(config);
    String dtPath  = getDelegationTokenPathConfigProperty(config);
    return gateway + (gateway.endsWith("/") ? "" : "/") + dtPath + (dtPath.endsWith("/") ? "" : "/");
  }

  /**
   * Validate the user requesting the token lifecycle action against the renewer specified for that token.
   *
   * @param candidate  The user requesting the change.
   * @param identifier The identifier for the token to be changed.
   *
   * @return true, if the user is valid according to the token identifier; Otherwise, false.
   *
   * @throws IllegalArgumentException
   */
  private static boolean validateRenewer(UserGroupInformation candidate, DelegationTokenIdentifier identifier)
      throws IllegalArgumentException {
    boolean isValid = true;

    Text declaredRenewer = identifier.getRenewer();
    if (declaredRenewer != null && declaredRenewer.getLength() > 0) {
      if (!declaredRenewer.toString().equals(candidate.getShortUserName())) {
        LOG.error(String.format(Locale.getDefault(),
                                ERR_INVALID_RENEWER,
                                candidate.getUserName(),
                                declaredRenewer));
        isValid = false;
      }
    } else {
      LOG.error("Operation not permitted. No renewer is specified in the identifier.");
      isValid = false;
    }

    return isValid;
  }

  /**
   * Invoke the specified token lifecycle request as the specified renewer user.
   *
   * @param endpoint  The request endpoint.
   * @param tokenData The token for which the request is being made.
   * @param renewer   The renewer user making the request.
   *
   * @return The response.
   *
   * @throws Exception
   */
  private static HttpResponse executeRequest(final String               endpoint,
                                             final String               tokenData,
                                             final UserGroupInformation renewer) throws Exception {
    HttpResponse response;

    final KnoxSession session = KnoxSession.kerberosLogin(endpoint);
    final HttpPost request = new HttpPost(endpoint);
    request.setEntity(new StringEntity(tokenData));

    if (renewer != null) {
      response = renewer.doAs((PrivilegedAction<HttpResponse>) () -> {
        try {
          return session.executeNow(request);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      });
    } else {
      response = session.executeNow(request);
    }

    return response;
  }

  private static Map<String, Object> parseJSONResponse(final String response) throws IOException {
    return (new ObjectMapper()).readValue(response, new TypeReference<Map<String, Object>>(){});
  }

}

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
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.knox.token.CloudAccessBrokerTokenRenew;
import org.apache.knox.gateway.shell.knox.token.CloudAccessBrokerTokenRevoke;
import org.apache.knox.gateway.shell.knox.token.Renew;
import org.apache.knox.gateway.shell.knox.token.Revoke;
import org.apache.knox.gateway.util.Tokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Base class for IDBroker delegation token renewer implementations.
 */
public abstract class AbstractIDBTokenRenewer extends TokenRenewer {

  private static final Logger LOG = LoggerFactory.getLogger(AbstractIDBTokenRenewer.class);

  private static final String ERR_INVALID_RENEWER =
                        "The user (%s) does not match the renewer declared for the token: %s";

  private final List<String> tokenEndpoints = new ArrayList<>();

  private RequestExecutor requestExecutor;

  @Override
  public boolean isManaged(final Token<?> token) throws IOException {
    return handleKind(token.getKind()); // These tokens can be renewed and canceled
  }

  @Override
  public long renew(final Token<?> token, final Configuration configuration) throws IOException, InterruptedException {
    long result = 0;

    TokenIdentifier identifier = token.decodeIdentifier();
    if (handleKind(identifier.getKind())) {
      LOG.info("Renewing " + identifier.toString());

      DelegationTokenIdentifier dtIdentifier = (DelegationTokenIdentifier) identifier;
      LOG.debug("Token: " + dtIdentifier.toString());

      // Default to the token's original expiration
      result = getTokenExpiration(dtIdentifier);

      final String accessToken = getAccessToken(dtIdentifier);
      if (accessToken == null || accessToken.isEmpty()) {
        LOG.info("Skipping Knox Token renewal because it's null or empty");
        return result;
      }

      UserGroupInformation user = UserGroupInformation.getCurrentUser();
      if (validateRenewer(user, dtIdentifier)) {
        try {
          LOG.info("Renewing access token: " + Tokens.getTokenDisplayText(accessToken));
          long response = requestRenewal(accessToken, configuration, user);
          if (response >= 0) {
            result = response;
          }
        } catch (Exception e) {
          LOG.error("Error renewing token: " + e.getMessage());
          throw new IOException("Error renewing token", e);
        }
      } else {
        throw new IOException("Invalid renewer: " + user.getShortUserName());
      }
    }

    LOG.debug("Updated token expiration: " + result);
    return result;
  }

  private long requestRenewal(final String accessToken,
                              final Configuration configuration,
                              final UserGroupInformation renewer)
          throws Exception {
    long result = -1;

    RequestExecutor re = getRequestExecutor(configuration);
    ClientContext context = ClientContext.with(re.getEndpoint());
    context.kerberos().enable(true);
    CloudAccessBrokerSession session = CloudAccessBrokerSession.create(context);
    Renew.Request request =
        org.apache.knox.gateway.shell.knox.token.Token.renew(session, accessToken, renewer.getShortUserName());

    BasicResponse response =
            renewer.doAs((PrivilegedAction<BasicResponse>) () -> re.execute(new CloudAccessBrokerTokenRenew(request)));

    String responseEntity = response.getString();
    int statusCode = response.getStatusCode();
    if (statusCode == HttpStatus.SC_OK) {
       if (response.getContentLength() > 0) {
         if (MediaType.APPLICATION_JSON.equals(response.getContentType())) {
           Map<String, Object> json = parseJSONResponse(responseEntity);
           boolean isRenewed = Boolean.parseBoolean((String) json.getOrDefault("renewed", "false"));
           if (isRenewed) {
             LOG.debug("Token renewed.");
             String expirationValue = (String) json.get("expires");
             if (expirationValue != null && !expirationValue.isEmpty()) {
               result = Long.parseLong(expirationValue);
             }
           } else {
             LOG.error("Token could not be renewed: " + json.get("error"));
             throw new IOException("Token could not be renewed: " + json.get("error"));
           }
         }
       }
    } else {
      LOG.error("Failed to renew token: " + statusCode);
      if (responseEntity != null) {
        LOG.error(responseEntity);
      }
      throw new IOException("Failed to renew token: " + statusCode);
    }

    return result;
  }

  @Override
  public void cancel(final Token<?> token, final Configuration configuration)
          throws IOException, InterruptedException {
    TokenIdentifier identifier = token.decodeIdentifier();
    if (handleKind(identifier.getKind())) {
      LOG.info("Canceling " + identifier.toString());

      DelegationTokenIdentifier dtIdentifier = (DelegationTokenIdentifier) identifier;
      LOG.debug("Token: " + dtIdentifier.toString());
      final String accessToken = getAccessToken(dtIdentifier);
      if (accessToken == null || accessToken.isEmpty()) {
        LOG.info("Skipping Knox Token revocation because it's null or empty");
        return;
      }

      UserGroupInformation user = UserGroupInformation.getCurrentUser();
      if (validateRenewer(user, dtIdentifier)) {
        try {
          LOG.info("Revoking access token: " + Tokens.getTokenDisplayText(accessToken));
          requestRevocation(accessToken, configuration, user);
        } catch (Exception e) {
          LOG.error("Error canceling token: " + e.getMessage());
          throw new IOException("Error canceling token", e);
        }
      } else {
        throw new IOException("Invalid renewer: " + user.getShortUserName());
      }
    }
  }

  private void requestRevocation(final String accessToken,
                                 final Configuration configuration,
                                 final UserGroupInformation renewer)
          throws Exception {

    RequestExecutor re = getRequestExecutor(configuration);
    ClientContext context = ClientContext.with(re.getEndpoint());
    context.kerberos().enable(true);
    CloudAccessBrokerSession session = CloudAccessBrokerSession.create(context);
    Revoke.Request request =
            org.apache.knox.gateway.shell.knox.token.Token.revoke(session, accessToken, renewer.getShortUserName());

    BasicResponse response =
          renewer.doAs((PrivilegedAction<BasicResponse>) () -> re.execute(new CloudAccessBrokerTokenRevoke(request)));

    String responseEntity = null;
    try {
      responseEntity = response.getString();
    } catch (Exception e) {
      // BasicResponse throws an exception if there is no entity
    }

    int statusCode = response.getStatusCode();
    if (statusCode == HttpStatus.SC_OK) {
      if (responseEntity != null && response.getContentLength() > 0) {
        if (MediaType.APPLICATION_JSON.equals(response.getContentType())) {
          Map<String, Object> json = parseJSONResponse(responseEntity);
          boolean isCanceled = Boolean.parseBoolean((String) json.getOrDefault("revoked", "false"));
          if (isCanceled) {
            LOG.info("Token canceled.");
          } else {
            final Object error = json.get("error");
            if (error == null) {
              LOG.info("Token was not canceled but there were not any errors. The token is probably marked as unused.");
            } else {
              LOG.error("Token could not be canceled: " + (String) error);
              throw new IOException("Token could not be canceled: " + json.get("error"));
            }
          }
        }
      }
    } else {
      LOG.error("Failed to cancel token: " + statusCode);
      boolean serverManagedTokenStateEnabled = true;
      if (responseEntity != null) {
        LOG.error(responseEntity);

        // Parse the response to determine whether this is due to server-managed token state being disabled
        Map<String, Object> json = parseJSONResponse(responseEntity);
        String error = (String) json.get("error");
        if (error.contains("not configured")) {
          serverManagedTokenStateEnabled = false; // it is disabled
        }
      }

      // If server-managed token state is enabled, then throw the exception
      if (serverManagedTokenStateEnabled) {
        throw new IOException("Failed to cancel token: " + statusCode);
      }
    }
  }

  /**
   * @return The value of the configuration property that specifies the IDBroker endpoint, which is the base for the
   *         delegation token endpoint.
   */
  protected abstract List<String> getGatewayAddressConfigProperty(Configuration config);

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
   * Get the expiration time encoded in the specified identifier.
   *
   * @param identifier A token identifier.
   * @return The identifier-specific expiration time.
   */
  protected abstract long getTokenExpiration(DelegationTokenIdentifier identifier);

  protected abstract RequestErrorHandlingAttributes getRequestErrorHandlingAttributes(Configuration configuration);

  /**
   * @param config The Configuration
   * @return The base endpoint(s) for token lifecycle requests.
   */
  private List<String> getTokenEndpoints(final Configuration config) {
    if (tokenEndpoints.isEmpty()) {
      String dtPath  = getDelegationTokenPathConfigProperty(config);
      List<String> gateways = getGatewayAddressConfigProperty(config);
      for (String gateway : gateways) {
        String tokenEndpoint = gateway + (gateway.endsWith("/") ? "" : "/") + dtPath;
        tokenEndpoints.add(tokenEndpoint);
      }
    }
    return tokenEndpoints;
  }

  protected RequestExecutor getRequestExecutor(final Configuration conf) {
    if (requestExecutor == null) {
      requestExecutor = new DefaultRequestExecutor(getTokenEndpoints(conf), getRequestErrorHandlingAttributes(conf));
    }
    return requestExecutor;
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
  private static boolean validateRenewer(final UserGroupInformation candidate,
                                         final DelegationTokenIdentifier identifier)
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

  private static Map<String, Object> parseJSONResponse(final String response) throws IOException {
    return (new ObjectMapper()).readValue(response, new TypeReference<Map<String, Object>>(){});
  }

}

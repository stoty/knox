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

import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.apache.knox.gateway.shell.KnoxSh;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;


public class DefaultRequestExecutor implements RequestExecutor {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultRequestExecutor.class);

  private static final List<Class<? extends Exception>> failoverExceptions =
        Arrays.asList(UnknownHostException.class,
                      NoRouteToHostException.class,
                      SocketException.class);

  /**
   * Manages the configured CloudAccessBroker endpoints.
   */
  private EndpointManager endpointManager;

  /**
   * Provides authentication tokens for the credentials requests in fail-over scenarios.
   */
  private AuthenticationTokenProvider authTokenProvider;

  private int maxFailoverAttempts = 3;
  private int maxRetryAttempts    = 3;

  private long failoverSleep = 1000;
  private long retrySleep    = 1000;


  public DefaultRequestExecutor(List<String> endpoints) {
    this(endpoints, null);
  }

  public DefaultRequestExecutor(List<String> endpoints, AuthenticationTokenProvider authTokenProvider) {
    this(new RandomEndpointManager(endpoints), authTokenProvider);
  }

  public DefaultRequestExecutor(EndpointManager             endpointManager,
                                AuthenticationTokenProvider authTokenProvider) {
    this.endpointManager = endpointManager;
    this.authTokenProvider = authTokenProvider;
  }

  /**
   *
   * @return The current target endpoint for requests from this client.
   */
  @Override
  public String getEndpoint() {
    return endpointManager.getActiveURL();
  }

  @Override
  public List<String> getConfiguredEndpoints() {
    return endpointManager.getURLs();
  }

  @Override
  public <T> T execute(AbstractCloudAccessBrokerRequest<T> request) {
    T response = null;

    try {
      response = request.now();
    } catch (KnoxShellException e) {
      LOG.error(e.getMessage());
      if (isFailoverException(e)) {
        if (request.failoverAttempts() < maxFailoverAttempts) {
          response = failoverRequest(request);
        } else {
          throw e;
        }
      } else {
        Throwable cause = e.getCause();
        if (ErrorResponse.class.isAssignableFrom(cause.getClass())) {
          throw (ErrorResponse) e.getCause();
        }
      }
    }

    return response;
  }

  <T> T failoverRequest(AbstractCloudAccessBrokerRequest<T> request) throws KnoxShellException {
    T response = null;

    String currentEndpoint = endpointManager.getActiveURL();
    String topology = request.getSession().base().substring(currentEndpoint.length());
    endpointManager.markFailed(currentEndpoint);

    CloudAccessBrokerSession cabSession = request.getSession();
    try {

      String authToken = null;
      if (authTokenProvider != null) {
        authTokenProvider.authenticate(endpointManager.getActiveURL());
      }

      cabSession.updateEndpoint(endpointManager.getActiveURL() + topology, authToken);
      request.recordFailoverAttempt();
      response = execute(request);
    } catch (ErrorResponse e) {
      throw e;
    } catch (Exception e) {
      if (e instanceof KnoxShellException) {
        throw ((KnoxShellException) e);
      } else {
        throw new KnoxShellException(e);
      }
    }

    return response;
  }


  /**
   * Determine if the specified exception represents an error condition that can be addressed with failover.
   *
   * @param e The KnoxShellException
   *
   * @return true, if the exception represents an error for which failover may help; otherwise, false.
   */
  private boolean isFailoverException(KnoxShellException e) {
    System.out.println(e.getMessage());
    Throwable cause = e.getCause();
    boolean isFailoverException = false;
    for (Class<? extends Exception> exceptionType : failoverExceptions) {
      if (exceptionType.isAssignableFrom(cause.getClass())) {
        isFailoverException = true;
        break;
      }
    }
    return isFailoverException;
  }


  /**
   * Determine if the specified exception represents an error condition that can be addressed with retry.
   *
   * @param e The KnoxShellException
   *
   * @return true, if the exception represents an error for which retry may help; otherwise, false.
   */
  private boolean isRetryException(KnoxShellException e) {
    // TODO: PJZ: Determine if the exception represents an error condition that can be overcome with retry.
    e.printStackTrace();
    System.out.println(e.getMessage());
    return false;
  }

}

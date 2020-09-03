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

import org.apache.http.HttpStatus;
import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.ErrorResponse;
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

  private static final List<Integer> retryStatusCodes =
          Arrays.asList(HttpStatus.SC_NOT_FOUND,
                        HttpStatus.SC_SERVICE_UNAVAILABLE,
                        HttpStatus.SC_GATEWAY_TIMEOUT);

  private static final List<Class<? extends Exception>> failoverExceptions =
          Arrays.asList(UnknownHostException.class,
                        NoRouteToHostException.class,
                        SocketException.class);

  /**
   * Manages the configured CloudAccessBroker endpoints.
   */
  private EndpointManager endpointManager;

  private int maxFailoverAttempts = 2;
  private int maxRetryAttempts    = 2;

  private long failoverSleep = 1000;
  private long retrySleep    = 5000;

  public DefaultRequestExecutor(List<String> endpoints) {
    this(new RandomEndpointManager(endpoints));
  }

  public DefaultRequestExecutor(EndpointManager endpointManager) {
    this.endpointManager = endpointManager;
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
  public <T> T execute(final AbstractCloudAccessBrokerRequest<T> request) {
    T response;

    try {
      response = request.now();
    } catch (KnoxShellException e) {
      LOG.error("Error executing request: {}", e.getMessage());
      if (isRetryException(e) && (request.retryAttempts() < maxRetryAttempts)) {
        try {
          Thread.sleep(retrySleep);
        } catch (InterruptedException ex) {
          //
        }
        request.recordRetryAttempt();
        LOG.debug("Request attempt {} ...", request.retryAttempts());
        response = execute(request);
      } else if (isFailoverException(e) && (getConfiguredEndpoints().size() > 1) && (request.failoverAttempts() < maxFailoverAttempts)) {
        LOG.debug("Failover attempt {} ...", (request.failoverAttempts() + 1));
        response = failoverRequest(request);
      } else {
        Throwable cause = e.getCause();
        if (ErrorResponse.class.isAssignableFrom(cause.getClass())) {
          throw (ErrorResponse) cause;
        } else {
          throw e;
        }
      }
    }

    return response;
  }

  <T> T failoverRequest(final AbstractCloudAccessBrokerRequest<T> request) throws KnoxShellException {
    T response;

    String currentEndpoint = endpointManager.getActiveURL();
    String topology = request.getSession().base().substring(currentEndpoint.length());
    endpointManager.markFailed(currentEndpoint);

    CloudAccessBrokerSession cabSession = request.getSession();
    try {
      String newEndpoint = endpointManager.getActiveURL();

      LOG.debug("Failing over to {}", newEndpoint);
      cabSession.updateEndpoint(newEndpoint + topology);

      try {
        Thread.sleep(failoverSleep);
      } catch (InterruptedException ex) {
        //
      }

      request.recordFailoverAttempt();
      response = execute(request);
    } catch (ErrorResponse | KnoxShellException e) {
      throw e;
    } catch (Exception e) {
      throw new KnoxShellException(e);
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
  private boolean isFailoverException(final KnoxShellException e) {
    boolean isFailoverException = false;

    Throwable cause = e.getCause();
    if (cause != null) {
      for (Class<? extends Exception> exceptionType : failoverExceptions) {
        if (exceptionType.isAssignableFrom(cause.getClass())) {
          isFailoverException = true;
          break;
        }
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
  private boolean isRetryException(final KnoxShellException e) {
    boolean result = false;

    Throwable cause = e.getCause();
    if (cause != null) {
      if (ErrorResponse.class.isAssignableFrom(cause.getClass())) {
        ErrorResponse response = (ErrorResponse) cause;
        result = retryStatusCodes.contains(response.getResponse().getStatusLine().getStatusCode());
      }
    }

    return result;
  }

}

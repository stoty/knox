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

import static java.util.Arrays.asList;
import static org.apache.http.HttpStatus.SC_GATEWAY_TIMEOUT;
import static org.apache.http.HttpStatus.SC_NOT_FOUND;
import static org.apache.http.HttpStatus.SC_SERVICE_UNAVAILABLE;
import static org.apache.knox.gateway.util.HttpUtils.isRelevantConnectionError;

import java.net.URL;
import java.util.List;
import java.util.Map;

import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class DefaultRequestExecutor implements RequestExecutor {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultRequestExecutor.class);

  private static final List<Integer> retryStatusCodes = asList(SC_NOT_FOUND, SC_SERVICE_UNAVAILABLE, SC_GATEWAY_TIMEOUT);

  /**
   * Manages the configured CloudAccessBroker endpoints.
   */
  private final EndpointManager endpointManager;

  private final RequestErrorHandlingAttributes requestErrorHandlingAttributes;

  public DefaultRequestExecutor(List<String> endpoints, RequestErrorHandlingAttributes requestErrorHandlingAttributes) {
    this(new RandomEndpointManager(endpoints), requestErrorHandlingAttributes);
  }

  public DefaultRequestExecutor(EndpointManager endpointManager, RequestErrorHandlingAttributes requestErrorHandlingAttributes) {
    this.endpointManager = endpointManager;
    this.requestErrorHandlingAttributes = requestErrorHandlingAttributes;
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
      if (shouldRetry(request, e)) {
        try {
          Thread.sleep(requestErrorHandlingAttributes.getRetrySleepInMillis());
        } catch (InterruptedException ex) {
          //
        }
        request.recordRetryAttempt();
        LOG.info("Retry attempt {} ...", request.retryAttempts());
        response = execute(request);
      } else if (shouldFailover(request, e)) {
        LOG.info("Failover attempt {} ...", (request.failoverAttempts() + 1));
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

  private <T> T failoverRequest(final AbstractCloudAccessBrokerRequest<T> request) throws KnoxShellException {
    T response;

    String currentEndpoint = endpointManager.getActiveURL();
    String topology = request.getSession().base().substring(currentEndpoint.length());
    endpointManager.markFailed(currentEndpoint);

    CloudAccessBrokerSession cabSession = request.getSession();
    try {
      String newEndpoint = endpointManager.getActiveURL();

      final Map<String, String> headers = cabSession.getHeaders();
      /* update the Host header so that we don't run into SNI issues after failover */
      final URL newUrl = new URL(newEndpoint);
      headers.put("Host", newUrl.getHost());
      cabSession.setHeaders(headers);

      LOG.info("Failing over to {}", newEndpoint);
      cabSession.updateEndpoint(newEndpoint + topology);
      LOG.info("Updated session endpoint base {}", cabSession.base());

      try {
        Thread.sleep(requestErrorHandlingAttributes.getFailoverSleepInMillis());
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

  private boolean shouldFailover(AbstractCloudAccessBrokerRequest<?> request, KnoxShellException e) {
    final boolean relevantConnectionError = isRelevantConnectionError(e.getCause());
    final boolean hasMoreEndpoints = getConfiguredEndpoints().size() > 1;
    final boolean attemptsNotExceeded = request.failoverAttempts() < requestErrorHandlingAttributes.getMaxFailoverAttempts();
    final boolean shouldFailover = relevantConnectionError && hasMoreEndpoints && attemptsNotExceeded;
    final String exceptionCause = e.getCause() == null ? "null" : e.getCause().getClass().getCanonicalName();
    LOG.info("Should failover = " + shouldFailover + " = [" + hasMoreEndpoints +" & " + attemptsNotExceeded + " & " + relevantConnectionError + " (" + exceptionCause + ")]");
    return shouldFailover;
  }

  private boolean shouldRetry(AbstractCloudAccessBrokerRequest<?> request, KnoxShellException e) {
    final boolean isRetryException = isRetryException(e);
    final boolean attemptsNotExceeded = request.retryAttempts() < requestErrorHandlingAttributes.getMaxRetryAttempts();
    final String exceptionCause = e.getCause() == null ? "null" : e.getCause().getClass().getCanonicalName();
    final boolean shouldRetry;
    if (isRetryException) {
      shouldRetry = attemptsNotExceeded;
      LOG.info("Should retry = " + shouldRetry + " = [" + attemptsNotExceeded + " & " +  isRetryException + " (" + exceptionCause + "))]");
    } else {
      final boolean hasOneEndpoint = getConfiguredEndpoints().size() == 1;
      final boolean relevantConnectionError = isRelevantConnectionError(e.getCause());
      shouldRetry = attemptsNotExceeded && hasOneEndpoint && relevantConnectionError;
      LOG.info("Should retry = " + shouldRetry + " = [" + attemptsNotExceeded + " & " + hasOneEndpoint + " & " + relevantConnectionError + " (" + exceptionCause + "))]");
    }
    return shouldRetry;
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

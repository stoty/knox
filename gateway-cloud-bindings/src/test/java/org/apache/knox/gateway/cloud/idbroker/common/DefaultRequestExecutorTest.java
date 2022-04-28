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
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.apache.knox.gateway.shell.TestableCloudAccessBrokerSession;
import org.apache.knox.gateway.shell.idbroker.AbstractBrokenCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwayNoRouteToHostCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysBadRequestCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysConnectExceptionCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysGatewayTimeoutCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysNotFoundCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysServiceUnavailableCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysSocketExceptionCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysUnknownHostCredentialsRequest;
import org.junit.Test;

import java.lang.reflect.Constructor;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DefaultRequestExecutorTest {

  private static final Map<Integer, Class<? extends AbstractBrokenCredentialsRequest>> testRequestTypes =
      new HashMap<>();
  static {
    testRequestTypes.put(HttpStatus.SC_NOT_FOUND, AlwaysNotFoundCredentialsRequest.class);
    testRequestTypes.put(HttpStatus.SC_SERVICE_UNAVAILABLE, AlwaysServiceUnavailableCredentialsRequest.class);
    testRequestTypes.put(HttpStatus.SC_GATEWAY_TIMEOUT, AlwaysGatewayTimeoutCredentialsRequest.class);
    testRequestTypes.put(HttpStatus.SC_BAD_REQUEST, AlwaysBadRequestCredentialsRequest.class);
  }


  private static final Map<Class, Class<? extends AbstractBrokenCredentialsRequest>> failoverRequestTypes =
      new HashMap<>();
  static {
    failoverRequestTypes.put(UnknownHostException.class, AlwaysUnknownHostCredentialsRequest.class);
    failoverRequestTypes.put(NoRouteToHostException.class, AlwayNoRouteToHostCredentialsRequest.class);
    failoverRequestTypes.put(ConnectException.class, AlwaysConnectExceptionCredentialsRequest.class);
    failoverRequestTypes.put(SocketException.class, AlwaysSocketExceptionCredentialsRequest.class);
  }

  private final RequestErrorHandlingAttributes validRequestErrorHandlingAtributes = new RequestErrorHandlingAttributes(2, 1, 2, 5);


  @Test
  public void test404RetryWithMultipleEndpoints() {
    doTestRetry(HttpStatus.SC_NOT_FOUND);
  }


  @Test
  public void test503RetryWithMultipleEndpoints() {
    doTestRetry(HttpStatus.SC_SERVICE_UNAVAILABLE);
  }


  @Test
  public void test504RetryWithMultipleEndpoints() {
    doTestRetry(HttpStatus.SC_GATEWAY_TIMEOUT);
  }

  @Test
  public void test400RetryWithOneEndpoint() {
    assertEquals(2, doTestRetry(Arrays.asList("https://host1:8443/gateway/"), HttpStatus.SC_BAD_REQUEST, true));
  }

  /**
   * Negative retry test case.
   * Retry should NOT be attempted for a Bad Request response and multiple endpoints.
   */
  @Test
  public void testNoRetry() {
    final List<String> endpoints = Arrays.asList("https://host1:8443/gateway/",
                                                 "https://host2:8443/gateway/");
    assertEquals(0, doTestRetry(endpoints, HttpStatus.SC_BAD_REQUEST, false));
  }

  @Test
  public void testUnknownHostFailoverWithSingleEndpoint() {
    final String topology = "mycab";
    final String endpoint = "http://host1:8443/gateway/";
    List<String> endpointUpdates =
        doTestFailover(Collections.singletonList(endpoint), topology, UnknownHostException.class);

    assertEquals("Expected 0 updates because there is only one endpoint.", 0, endpointUpdates.size());
  }

  @Test
  public void testConnectExceptionFailoverWithTwoEndpoint() {
    final String topology = "mycab";
    final String[] endpoints = {"http://host1:8443/gateway/", "http://host2:8443/gateway/"};
    List<String> endpointUpdates =
        doTestFailover(Arrays.asList(endpoints), topology, ConnectException.class);

    assertEquals("Expected 2 updates because maxFailoverAttempts is 2.", 2, endpointUpdates.size());
    assertEquals(endpoints[1], endpointUpdates.get(0).substring(0, endpoints[1].length()));
    assertEquals(endpoints[0], endpointUpdates.get(1).substring(0, endpoints[0].length()));
  }

  @Test
  public void testDefaultMaxFailoverAttempts() {
    final String topology = "mycab";
    final String[] endpoints = {"http://host1:8443/gateway/",
                                "http://host2:8443/gateway/",
                                "http://host3:8443/gateway/",
                                "http://host4:8443/gateway/"};
    List<String> endpointUpdates =
        doTestFailover(Arrays.asList(endpoints), topology, ConnectException.class);

    assertEquals("Expected 2 updates because maxFailoverAttempts is 2.", 2, endpointUpdates.size());
    assertEquals(endpoints[1], endpointUpdates.get(0).substring(0, endpoints[1].length()));
    assertEquals(endpoints[2], endpointUpdates.get(1).substring(0, endpoints[2].length()));
  }

  @Test
  public void testUnknownHostFailoverWithMultipleEndpoints() {
    doTestFailoverWithMultipleEndpoints(UnknownHostException.class);
  }

  @Test
  public void testNoRouteToHostFailoverWithMultipleEndpoints() {
    doTestFailoverWithMultipleEndpoints(NoRouteToHostException.class);
  }

  @Test
  public void testConnectExceptionFailoverWithMultipleEndpoints() {
    doTestFailoverWithMultipleEndpoints(ConnectException.class);
  }

  @Test
  public void testSocketExceptionFailoverWithMultipleEndpoints() {
    doTestFailoverWithMultipleEndpoints(SocketException.class);
  }


  private void doTestFailoverWithMultipleEndpoints(final Class<? extends Exception> exceptionClass) {
    final String topology = "gcp-cab";
    final List<String> endpoints = Arrays.asList("http://host1:8443/gateway/",
                                                 "http://host2:8443/gateway/",
                                                 "http://host3:8443/gateway/");

    List<String> endpointUpdates = doTestFailover(endpoints, topology, exceptionClass);
    assertEquals("Expected 2 updates because maxFailoverAttempts is 2.", 2, endpointUpdates.size());
    assertEquals(endpoints.get(1), endpointUpdates.get(0).substring(0, endpoints.get(1).length()));
    assertEquals(endpoints.get(2), endpointUpdates.get(1).substring(0, endpoints.get(2).length()));
  }

  private List<String> doTestFailover(final List<String>               endpoints,
                                      final String                     topology,
                                      final Class<? extends Exception> exceptionClass) {
    ClientContext clientContext = ClientContext.with(endpoints.get(0) + topology);

    TestableCloudAccessBrokerSession session = null;
    try {
      session = new TestableCloudAccessBrokerSession(clientContext);
    } catch (Exception e) {
      fail("Couldn't even create the session: " + e.getMessage());
    }

    DefaultRequestExecutor exec = new DefaultRequestExecutor(new DefaultEndpointManager(endpoints), validRequestErrorHandlingAtributes);
    try {
      exec.execute(getTestRequest(exceptionClass, session));
      fail("Expected an exception");
    } catch (KnoxShellException e) {
      // expected
      Throwable cause = e.getCause();
      assertTrue(exceptionClass.isAssignableFrom(cause.getClass()));
    }

    List<String> endpointUpdates = session.getEndpointUpdates();
    assertNotNull(endpointUpdates);

    return endpointUpdates;
  }


  private void doTestRetry(int expectedStatusCode) {
    final List<String> endpoints = Arrays.asList("https://host1:8443/gateway/",
                                                 "https://host2:8443/gateway/");
    assertEquals(2, doTestRetry(endpoints, expectedStatusCode, false));
  }

  private int doTestRetry(final List<String> endpoints, final int expectedStatusCode, boolean returnConnectionError) {
    final String topology = "test-cab";

    ClientContext clientContext = ClientContext.with(endpoints.get(0) + topology);

    TestableCloudAccessBrokerSession session = null;
    try {
      session = new TestableCloudAccessBrokerSession(clientContext);
    } catch (Exception e) {
      fail("Couldn't even create the session: " + e.getMessage());
    }

    DefaultRequestExecutor exec = new DefaultRequestExecutor(new DefaultEndpointManager(endpoints), validRequestErrorHandlingAtributes);
    AbstractBrokenCredentialsRequest request = returnConnectionError ? getTestRequest(UnknownHostException.class, session) : getTestRequest(expectedStatusCode, session);
    assertNotNull("There is no valid request type available for the specified status code.", request);
    try {
      exec.execute(request);
      fail("Expected an exception");
    } catch (ErrorResponse e) {
      // expected
      assertFalse(returnConnectionError);
      assertEquals(request.getStatusCode(), e.getResponse().getStatusLine().getStatusCode());
    } catch (KnoxShellException e) {
      assertTrue(returnConnectionError);
      Throwable cause = e.getCause();
      assertTrue(UnknownHostException.class.isAssignableFrom(cause.getClass()));
    }

    List<String> endpointUpdates = session.getEndpointUpdates();
    assertNotNull(endpointUpdates);
    assertTrue("Expected no endpoint updates because retry should have been triggered instead.",
               endpointUpdates.isEmpty());

    return request.retryAttempts();
  }

  /**
   * This test case makes sure that when there
   * is a retry the HOST header that is sent
   * as part of the request has the failover hostname.
   * Without this we'll get
   * "SNI Mismatch Failures due to Wrong Host Header".
   */
  @Test
  public void testHostHeaderForRetry() {

    final RequestErrorHandlingAttributes requestErrorHandlingAtributes = new RequestErrorHandlingAttributes(3, 1, 2, 5);

    final List<String> endpoints = Arrays.asList("https://host1:8443/gateway/",
            "https://host2:8443/gateway/");

    final String topology = "test-cab";

    ClientContext clientContext = ClientContext.with(endpoints.get(0) + topology);

    TestableCloudAccessBrokerSession session = null;
    try {
      session = new TestableCloudAccessBrokerSession(clientContext);
    } catch (Exception e) {
      fail("Couldn't even create the session: " + e.getMessage());
    }

    /* no headers are added prior to failover */
    assertTrue(session.getHeaders().isEmpty());

    DefaultRequestExecutor exec = new DefaultRequestExecutor(new DefaultEndpointManager(endpoints), requestErrorHandlingAtributes);
    try {
      exec.execute(getTestRequest(ConnectException.class, session));
      fail("Expected an exception");
    } catch (KnoxShellException e) {
      // expected
      Throwable cause = e.getCause();
      assertTrue(ConnectException.class.isAssignableFrom(cause.getClass()));
    }

    /* headers are added after failover */
    assertFalse(session.getHeaders().isEmpty());
    /* make sure correct host header is added after failover */
    assertTrue(endpoints.get(1).contains(session.getHeaders().get("Host")));
  }


  /**
   * Get a test request object based on the specified HTTP response status code
   */
  private static AbstractBrokenCredentialsRequest getTestRequest(int                      statusCode,
                                                                 CloudAccessBrokerSession session) {
    return createTestRequest(testRequestTypes.get(statusCode), session);
  }

  /**
   * Get a test request object based on the specified exception type
   */
  private static AbstractBrokenCredentialsRequest getTestRequest(Class                    exceptionType,
                                                                 CloudAccessBrokerSession session) {
    return createTestRequest(failoverRequestTypes.get(exceptionType), session);
  }

  /**
   *
   * @param clazz The AbstractBrokenCredentialsRequest class to instantiate.
   * @param session The CloudAccessBrokerSession to apply to the instantiation.
   * @return The instance.
   */
  private static AbstractBrokenCredentialsRequest createTestRequest(Class<? extends AbstractBrokenCredentialsRequest> clazz,
                                                                    CloudAccessBrokerSession session) {
    AbstractBrokenCredentialsRequest instance = null;

    if (clazz != null && AbstractBrokenCredentialsRequest.class.isAssignableFrom(clazz)) {
      try {
        Constructor<? extends AbstractBrokenCredentialsRequest> ctor =
                                        clazz.getDeclaredConstructor(CloudAccessBrokerSession.class);
        instance = ctor.newInstance(session);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }

    return instance;
  }

}

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

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.apache.knox.gateway.shell.TestableCloudAccessBrokerSession;
import org.apache.knox.gateway.shell.idbroker.AbstractBrokenCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysBadRequestCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysGatewayTimeoutCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysNotFoundCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.AlwaysServiceUnavailableCredentialsRequest;
import org.apache.knox.gateway.shell.idbroker.Credentials;
import org.easymock.EasyMock;
import org.junit.Test;

import java.lang.reflect.Constructor;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DefaultRequestExecutorTest {

  private static final Map<Integer, Class> testRequestTypes = new HashMap<>();
  static {
    testRequestTypes.put(HttpStatus.SC_NOT_FOUND, AlwaysNotFoundCredentialsRequest.class);
    testRequestTypes.put(HttpStatus.SC_SERVICE_UNAVAILABLE, AlwaysServiceUnavailableCredentialsRequest.class);
    testRequestTypes.put(HttpStatus.SC_GATEWAY_TIMEOUT, AlwaysGatewayTimeoutCredentialsRequest.class);
    testRequestTypes.put(HttpStatus.SC_BAD_REQUEST, AlwaysBadRequestCredentialsRequest.class);
  }


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

  /**
   * Negative retry test case.
   * Retry should NOT be attempted for a Bad Request response.
   */
  @Test
  public void testNoRetry() {
    final String topology = "gcp-cab";
    final List<String> endpoints = Arrays.asList("https://host1:8443/gateway/",
                                                 "https://host2:8443/gateway/");
    assertEquals(0, doTestRetry(endpoints, topology, HttpStatus.SC_BAD_REQUEST));
  }



  @Test
  public void testUnknownHostFailoverWithSingleEndpoint() {
    final String topology = "mycab";
    final String endpoint = "http://host1:8443/gateway/";
    List<String> endpointUpdates = doTestFailover(Collections.singletonList(endpoint), topology);
    assertEquals(endpoint, endpointUpdates.get(0).substring(0, endpoint.length()));
    assertEquals(endpoint, endpointUpdates.get(1).substring(0, endpoint.length()));
    assertEquals(endpoint, endpointUpdates.get(2).substring(0, endpoint.length()));
  } // TODO: PJZ: Should max failover attempts be constrained by the number of available endpoints?
    //       In other words, if there is only one endpoint, should max failover attempts be reduced to one?


  @Test
  public void testUnknownHostFailoverWithMultipleEndpoints() {
    final String topology = "gcp-cab";
    final List<String> endpoints = Arrays.asList("http://host1:8443/gateway/",
                                                 "http://host2:8443/gateway/",
                                                 "http://host3:8443/gateway/");
    List<String> endpointUpdates = doTestFailover(endpoints, topology);
    assertEquals(endpoints.get(1), endpointUpdates.get(0).substring(0, endpoints.get(1).length()));
    assertEquals(endpoints.get(2), endpointUpdates.get(1).substring(0, endpoints.get(2).length()));
    assertEquals(endpoints.get(0), endpointUpdates.get(2).substring(0, endpoints.get(0).length()));
  }


  @Test
  public void testUnknownHostFailoverWithMultipleEndpointsAndAuthTokenProvider() {
    final String topology = "gcp-cab";
    final List<String> endpoints = Arrays.asList("http://host1:8443/gateway/",
                                                 "http://host2:8443/gateway/",
                                                 "http://host3:8443/gateway/");

    List<String> endpointUpdates = doTestFailover(endpoints, topology);

    assertEquals(endpoints.get(1), endpointUpdates.get(0).substring(0, endpoints.get(1).length()));
    assertEquals(endpoints.get(2), endpointUpdates.get(1).substring(0, endpoints.get(2).length()));
    assertEquals(endpoints.get(0), endpointUpdates.get(2).substring(0, endpoints.get(0).length()));
  }


  private List<String> doTestFailover(final List<String>                endpoints,
                                      final String                      topology) {
    ClientContext clientContext = ClientContext.with(endpoints.get(0) + topology);

    TestableCloudAccessBrokerSession session = null;
    try {
      session = new TestableCloudAccessBrokerSession(clientContext);
    } catch (Exception e) {
      fail("Couldn't even create the session: " + e.getMessage());
    }

    IDBClient<AccessTokenProvider.AccessToken> mockClient =
        (IDBClient<AccessTokenProvider.AccessToken>) EasyMock.createNiceMock(IDBClient.class);

    DefaultRequestExecutor exec = new DefaultRequestExecutor(new DefaultEndpointManager(endpoints));
    try {
      exec.execute(Credentials.get(session));
      fail("Expected an exception");
    } catch (KnoxShellException e) {
      // expected
      Throwable cause = e.getCause();
      assertTrue(UnknownHostException.class.isAssignableFrom(cause.getClass()));
    }

    List<String> endpointUpdates = session.getEndpointUpdates();
    assertNotNull(endpointUpdates);
    assertEquals("Expected 3 updates because maxFailoverAttempts is 3.", 3, endpointUpdates.size());

    return endpointUpdates;
  }


  private void doTestRetry(int expectedStatusCode) {
    final String topology = "gcp-cab";
    final List<String> endpoints = Arrays.asList("https://host1:8443/gateway/",
                                                 "https://host2:8443/gateway/");
    assertEquals(3, doTestRetry(endpoints, topology, expectedStatusCode));
  }


  private int doTestRetry(final List<String> endpoints,
                          final String       topology,
                          final int          expectedStatusCode) {
    ClientContext clientContext = ClientContext.with(endpoints.get(0) + topology);

    TestableCloudAccessBrokerSession session = null;
    try {
      session = new TestableCloudAccessBrokerSession(clientContext);
    } catch (Exception e) {
      fail("Couldn't even create the session: " + e.getMessage());
    }

    DefaultRequestExecutor exec = new DefaultRequestExecutor(new DefaultEndpointManager(endpoints));
    AbstractBrokenCredentialsRequest request = getTestRequest(expectedStatusCode, session);
    assertNotNull("There is no valid request type available for the specified status code.", request);
    try {
      exec.execute(request);
      fail("Expected an exception");
    } catch (ErrorResponse e) {
      // expected
      assertEquals(request.getStatusCode(), e.getResponse().getStatusLine().getStatusCode());
    }

    List<String> endpointUpdates = session.getEndpointUpdates();
    assertNotNull(endpointUpdates);
    assertTrue("Expected no endpoint updates because retry should have been triggered instead.",
               endpointUpdates.isEmpty());

    return request.retryAttempts();
  }


  private static AbstractBrokenCredentialsRequest getTestRequest(int statusCode, CloudAccessBrokerSession session) {
    AbstractBrokenCredentialsRequest instance = null;

    Class<?> clazz = testRequestTypes.get(statusCode);
    if (clazz != null && AbstractBrokenCredentialsRequest.class.isAssignableFrom(clazz)) {
      try {
        Constructor<AbstractBrokenCredentialsRequest> ctor =
            ((Class<AbstractBrokenCredentialsRequest>)clazz).getDeclaredConstructor(CloudAccessBrokerSession.class);
        instance = ctor.newInstance(session);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }

    return instance;
  }

}

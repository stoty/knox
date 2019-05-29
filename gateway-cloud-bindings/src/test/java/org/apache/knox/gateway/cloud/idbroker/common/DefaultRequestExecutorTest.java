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
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.KnoxAuthTokenProvider;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.ClientContext;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.apache.knox.gateway.shell.TestableCloudAccessBrokerSession;
import org.apache.knox.gateway.shell.idbroker.Credentials;
import org.easymock.EasyMock;
import org.junit.Test;

import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DefaultRequestExecutorTest {

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
    final AuthenticationTokenProvider atp = EasyMock.createNiceMock(AuthenticationTokenProvider.class);
    EasyMock.expect(atp.authenticate(endpoints.get(1))).andReturn("TEST_AUTH_TOKEN_ONE");
    EasyMock.expect(atp.authenticate(endpoints.get(2))).andReturn("TEST_AUTH_TOKEN_TWO");
    EasyMock.expect(atp.authenticate(endpoints.get(0))).andReturn("TEST_AUTH_TOKEN_THREE");
    EasyMock.replay(atp);

    List<String> endpointUpdates = doTestFailover(endpoints, topology, atp);

    EasyMock.verify(atp);

    assertEquals(endpoints.get(1), endpointUpdates.get(0).substring(0, endpoints.get(1).length()));
    assertEquals(endpoints.get(2), endpointUpdates.get(1).substring(0, endpoints.get(2).length()));
    assertEquals(endpoints.get(0), endpointUpdates.get(2).substring(0, endpoints.get(0).length()));
  }


  public List<String> doTestFailover(final List<String> endpoints, String topology) {
    return doTestFailover(endpoints, topology, null);
  }

  public List<String> doTestFailover(final List<String> endpoints,
                                     final String topology,
                                     final AuthenticationTokenProvider authTokenProvider) {
    ClientContext clientContext = ClientContext.with(endpoints.get(0) + topology);

    TestableCloudAccessBrokerSession session = null;
    try {
      session = new TestableCloudAccessBrokerSession(clientContext);
    } catch (Exception e) {
      fail("Couldn't even create the session: " + e.getMessage());
    }

    IDBClient<AccessTokenProvider.AccessToken> mockClient =
        (IDBClient<AccessTokenProvider.AccessToken>) EasyMock.createNiceMock(IDBClient.class);

    AuthenticationTokenProvider atp = authTokenProvider;
    if (atp == null) {
      atp = new TestAuthTokenProvider(mockClient, new Configuration());
    }

    DefaultRequestExecutor exec = new DefaultRequestExecutor(new DefaultEndpointManager(endpoints), atp);
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


  private static final class TestAuthTokenProvider extends KnoxAuthTokenProvider {
    TestAuthTokenProvider(IDBClient<?> client, Configuration conf) {
      super(client, conf);
    }

    @Override
    public String authenticate(String tokenAddress) {
      return "DUMMY_AUTH_TOKEN";
    }
  }

}

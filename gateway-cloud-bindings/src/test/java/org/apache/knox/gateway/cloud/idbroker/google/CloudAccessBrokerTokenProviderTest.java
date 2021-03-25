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

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.eq;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.KnoxToken;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.test.category.UnitTests;
import org.easymock.EasyMock;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.IOException;
import java.net.URI;

@Category(UnitTests.class)
public class CloudAccessBrokerTokenProviderTest {

  /**
   * Test getting credentials from the default /credentials API without having initialized a delegation token
   */
  @Test(expected = IllegalStateException.class)
  public void testDefaultGetCredentialsMissingDelegationToken() throws Exception {
    IDBClient<AccessTokenProvider.AccessToken> client = createIDBClientMock();
    EasyMock.expect(client.hasKerberosCredentials()).andReturn(false);
    EasyMock.expect(client.shouldUseKerberos()).andReturn(false);
    EasyMock.expect(client.createKnoxDTSession(anyObject(Configuration.class))).andReturn(Pair.of(null,null)).anyTimes();
    EasyMock.expect(client.createKnoxCABSession(anyObject(KnoxToken.class))).andReturn(null).anyTimes();
    EasyMock.expect(client.requestKnoxDelegationToken(anyObject(KnoxSession.class), anyString(), anyObject(URI.class))).andReturn(null).anyTimes();
    EasyMock.replay(client);
    invokeCloudAccessBrokerTokenProvider(client,
        null,
        null,
        0,
        "DUMMY_GCP_TOKEN",
        (60 * 60 * 1000));
  }


  /**
   * Test getting credentials when the existing credentials are soon-to-expire
   */
  @Test
  public void testGetExpiringCredentials() throws Exception {
    final String DT_TYPE = "Bearer";
    final String DT = "DELEGATION_TOKEN_DUMMY";
    final long DT_EXPIRES = System.currentTimeMillis() + (60 * 60 * 1000); // now + 1 hour
    final String GCP_TOKEN = "GOOGLE_TOKEN_DUMMY";
    final long GCP_TOKEN_EXP = System.currentTimeMillis() + (60 * 1000); // now + 1 minute

    AccessTokenProvider.AccessToken testAccessToken = new AccessTokenProvider.AccessToken(GCP_TOKEN, GCP_TOKEN_EXP);

    KnoxToken knoxToken = new KnoxToken("test", DT, DT_TYPE, DT_EXPIRES, null, true);

    IDBClient<AccessTokenProvider.AccessToken> mockClient = createIDBClientMock();
    EasyMock.expect(mockClient.createKnoxCABSession(eq(knoxToken))).andReturn(null);
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
        .andReturn(testAccessToken);

    EasyMock.replay(mockClient);

    // First, try getting an access token, one which has not expired and is not about to expire
    AccessTokenProvider.AccessToken at = invokeCloudAccessBrokerTokenProvider(mockClient, DT, DT_TYPE, DT_EXPIRES, GCP_TOKEN, GCP_TOKEN_EXP);

    assertNotNull(at);

    EasyMock.reset(mockClient);
    EasyMock.expect(mockClient.hasKerberosCredentials()).andReturn(false);
    EasyMock.expect(mockClient.shouldUseKerberos()).andReturn(false);
    EasyMock.expect(mockClient.createKnoxCABSession(knoxToken)).andReturn(null);
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
        .andReturn(testAccessToken);
    EasyMock.replay(mockClient);

    // Try to get an access token when the existing one is about to expire (or has expired)
    CloudAccessBrokerTokenProvider tp = new CloudAccessBrokerTokenProvider(mockClient, knoxToken, GCP_TOKEN, System.currentTimeMillis());
    tp.setConf(new Configuration());
    assertEquals(testAccessToken, tp.getAccessToken());
  }


  /**
   * Test getting existing valid credentials with a valid delegation token.
   */
  @Test
  public void testGetCredentialsWithValidDT() throws Exception {
    final String DT_TYPE = "Bearer";
    final String DT = "DELEGATION_TOKEN_DUMMY";
    final long DT_EXPIRES = System.currentTimeMillis() + (10 * 60 * 1000); // now + 10 minutes
    final String GCP_TOKEN = "GOOGLE_TOKEN_DUMMY";
    final long GCP_TOKEN_EXP = System.currentTimeMillis() + (60 * 1000); // now + 1 minute

    AccessTokenProvider.AccessToken testAccessToken = new AccessTokenProvider.AccessToken(GCP_TOKEN, GCP_TOKEN_EXP);

    IDBClient<AccessTokenProvider.AccessToken> mockClient = createIDBClientMock();

    // Request to create a session based on the existing DT
    EasyMock.expect(mockClient.createKnoxCABSession(anyString(), eq("Bearer"))).andReturn(null);

    // There should be only one request to get GCP credentials using the still-valid DT
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
        .andReturn(testAccessToken);

    EasyMock.replay(mockClient);

    // Try getting an access token with a DT that has not yet expired but is about to expire
    invokeCloudAccessBrokerTokenProvider(mockClient, DT, DT_TYPE, DT_EXPIRES, GCP_TOKEN, GCP_TOKEN_EXP);
  }


  /**
   * Test getting existing valid credentials with a soon-to-expire delegation token.
   */
  @Test
  public void testGetCredentialsWithExpiringDT() throws Exception {
    final String DT_TYPE = "Bearer";
    final String DT = "DELEGATION_TOKEN_DUMMY";
    final long DT_EXPIRES = (System.currentTimeMillis() / 1000) + (90); // now + 1.5 minutes, in seconds

    IDBClient<AccessTokenProvider.AccessToken> mockClient = createIDBClientMock();

    // Request to create a session based on the existing DT
    EasyMock.expect(mockClient.createKnoxCABSession(anyObject(KnoxToken.class))).andReturn(null).anyTimes();

    final String GCP_TOKEN = "GOOGLE_TOKEN_DUMMY";
    final long GCP_TOKEN_EXP = System.currentTimeMillis() + (60 * 1000); // now + 1 minute
    final AccessTokenProvider.AccessToken gcpToken = new AccessTokenProvider.AccessToken(GCP_TOKEN, GCP_TOKEN_EXP);
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
            .andReturn(gcpToken)
            .anyTimes();

    EasyMock.replay(mockClient);

    // Try getting an access token with a DT that has not yet expired but is about to expire; It should be allowed
    try {
      invokeCloudAccessBrokerTokenProvider(mockClient,
                                           DT,
                                           DT_TYPE,
                                           DT_EXPIRES,
                                           gcpToken.getToken(),
                                           gcpToken.getExpirationTimeMilliSeconds());
    } catch (IllegalStateException e) {
      fail("Unexpected exception.");
    }
  }


  /**
   * Test getting existing valid credentials with an expired delegation token.
   */
  @Test
  public void testGetCredentialsWithExpiredDT() throws Exception {
    final String DT_TYPE = "Bearer";
    final String DT = "DELEGATION_TOKEN_DUMMY";
    final long DT_EXPIRES = System.currentTimeMillis() / 1000; // now, in seconds

    IDBClient<AccessTokenProvider.AccessToken> mockClient = createIDBClientMock();
    EasyMock.expect(mockClient.createKnoxCABSession(anyObject(KnoxToken.class))).andReturn(null).anyTimes();

    // Since the DT has expired, simulate a 401 from the attempt to get cloud credentials from IDBroker
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
            .andThrow(new IOException("HTTP/1.1 401 Unauthorized"))
            .anyTimes();
    EasyMock.expect(mockClient.hasKerberosCredentials()).andReturn(false);
    EasyMock.expect(mockClient.shouldUseKerberos()).andReturn(false);
    EasyMock.replay(mockClient);

    // Try getting an access token with a DT that has expired; It should be rejected
    try {
      invokeCloudAccessBrokerTokenProvider(mockClient, DT, DT_TYPE, DT_EXPIRES, null, -1);
      fail("Expected an exception.");
    } catch (Exception e) {
      assertTrue(e.getMessage().contains("401"));
    }
  }


  // Internal test method
  private AccessTokenProvider.AccessToken invokeCloudAccessBrokerTokenProvider(final IDBClient<AccessTokenProvider.AccessToken> client,
                                                                               final String delegationToken,
                                                                               final String delegationTokenType,
                                                                               final long delegationTokenExpiration,
                                                                               final String gcpToken,
                                                                               final long gcpTokenExpiration) {
    CloudAccessBrokerTokenProvider tp =
        new CloudAccessBrokerTokenProvider(client,
            new KnoxToken("test", delegationToken, delegationTokenType, delegationTokenExpiration, null, true),
            gcpToken,
            gcpTokenExpiration);
    tp.setConf(new Configuration());
    AccessTokenProvider.AccessToken at = tp.getAccessToken();
    assertNotNull(at);
    assertEquals(gcpToken, at.getToken());
    assertEquals(gcpTokenExpiration, (long) at.getExpirationTimeMilliSeconds());
    return at;
  }


  @SuppressWarnings("unchecked")
  private static IDBClient<AccessTokenProvider.AccessToken> createIDBClientMock() {
    return (IDBClient<AccessTokenProvider.AccessToken>) EasyMock.createMock(IDBClient.class);
  }

}

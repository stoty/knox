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

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.test.category.UnitTests;
import org.easymock.EasyMock;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.eq;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@Category(UnitTests.class)
public class CloudAccessBrokerTokenProviderTest {

  private static final Logger LOG =
      LoggerFactory.getLogger(CloudAccessBrokerTokenProviderTest.class);


  /**
   * Test getting credentials from the default /credentials API without having initialized a delegation token
   */
  @Test(expected = IllegalArgumentException.class)
  public void testDefaultGetCredentialsMissingDelegationToken() throws Exception {
    IDBClient<AccessTokenProvider.AccessToken> client = createIDBClientMock();
    EasyMock.replay(client);
    invokeCloudAccessBrokerTokenProvider(client,
                                         null,
                                         null,
                                         0,
                                         "https://localhost:8443/gateway/cab",
                                         "DUMMY_GCP_TOKEN",
                                         (60 * 60 * 1000));
  }


  /**
   * Test getting credentials when the existing credentials are soon-to-expire
   */
  @Test
  public void testGetExpiringCredentials() throws Exception {
    final String CAB_URL =
        CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS + CloudAccessBrokerClientTestUtils.CAB_PATH;

    final String DT_TYPE       = "Bearer";
    final String DT            = "DELEGATION_TOKEN_DUMMY";
    final long   DT_EXPIRES    =  System.currentTimeMillis() + (60 * 60 * 1000); // now + 1 hour
    final String GCP_TOKEN     = "GOOGLE_TOKEN_DUMMY";
    final Long   GCP_TOKEN_EXP = System.currentTimeMillis() + (60 * 1000); // now + 1 minute

    AccessTokenProvider.AccessToken testAccessToken = new AccessTokenProvider.AccessToken(GCP_TOKEN, GCP_TOKEN_EXP);

    IDBClient<AccessTokenProvider.AccessToken> mockClient = createIDBClientMock();
    EasyMock.expect(mockClient.cloudSessionFromDelegationToken(anyString(), eq("Bearer"))).andReturn(null);
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
            .andReturn(testAccessToken);

    EasyMock.replay(mockClient);

    // First, try getting an access token, one which has not expired and is not about to expire
    invokeCloudAccessBrokerTokenProvider(mockClient, DT, DT_TYPE, DT_EXPIRES, CAB_URL, GCP_TOKEN, GCP_TOKEN_EXP);

    EasyMock.reset(mockClient);
    EasyMock.expect(mockClient.cloudSessionFromDelegationToken(anyString(), eq("Bearer"))).andReturn(null);
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
            .andReturn(testAccessToken);
    EasyMock.replay(mockClient);

    // Try to get an access token when the existing one is about to expire (or has expired)
    CloudAccessBrokerTokenProvider tp =
        new CloudAccessBrokerTokenProvider(mockClient,
                                           DT,
                                           DT_TYPE,
                                           CAB_URL,
                                           DT_EXPIRES,
                                           GCP_TOKEN,
                                           System.currentTimeMillis());
    tp.setConf(new Configuration());
    assertEquals(testAccessToken, tp.getAccessToken());
  }


  /**
   * Test getting existing valid credentials with a valid delegation token.
   */
  @Test
  public void testGetCredentialsWithValidDT() throws Exception {
    final String CAB_URL =
        CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS + CloudAccessBrokerClientTestUtils.CAB_PATH;

    final String DT_TYPE       = "Bearer";
    final String DT            = "DELEGATION_TOKEN_DUMMY";
    final long   DT_EXPIRES    =  System.currentTimeMillis() + (10 * 60 * 1000); // now + 10 mins
    final String GCP_TOKEN     = "GOOGLE_TOKEN_DUMMY";
    final Long   GCP_TOKEN_EXP = System.currentTimeMillis() + (60 * 1000); // now + 1 minute

    AccessTokenProvider.AccessToken testAccessToken = new AccessTokenProvider.AccessToken(GCP_TOKEN, GCP_TOKEN_EXP);

    IDBClient<AccessTokenProvider.AccessToken> mockClient = createIDBClientMock();

    // Request to create a session based on the existing DT
    EasyMock.expect(mockClient.cloudSessionFromDelegationToken(anyString(), eq("Bearer"))).andReturn(null);

    // There should be only one request to get GCP credentials using the still-valid DT
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
            .andReturn(testAccessToken);

    EasyMock.replay(mockClient);

    // Try getting an access token with a DT that has not yet expired but is about to expire
    invokeCloudAccessBrokerTokenProvider(mockClient, DT, DT_TYPE, DT_EXPIRES, CAB_URL, GCP_TOKEN, GCP_TOKEN_EXP);
  }


  /**
   * Test getting existing valid credentials with a soon-to-expire delegation token.
   */
  @Test
  public void testGetCredentialsWithExpiringDT() throws Exception {
    final String CAB_URL =
        CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS + CloudAccessBrokerClientTestUtils.CAB_PATH;

    final String DT_TYPE       = "Bearer";
    final String DT            = "DELEGATION_TOKEN_DUMMY";
    final long   DT_EXPIRES    =  System.currentTimeMillis() + (5 * 60 * 1000); // now + 5 mins
    final String GCP_TOKEN     = "GOOGLE_TOKEN_DUMMY";
    final Long   GCP_TOKEN_EXP = System.currentTimeMillis() + (60 * 1000); // now + 1 minute

    AccessTokenProvider.AccessToken testAccessToken = new AccessTokenProvider.AccessToken(GCP_TOKEN, GCP_TOKEN_EXP);

    IDBClient<AccessTokenProvider.AccessToken> mockClient = createIDBClientMock();

    // Request to create a session based on the existing DT
    EasyMock.expect(mockClient.cloudSessionFromDelegationToken(anyString(), eq("Bearer"))).andReturn(null);

    RequestDTResponseMessage dtResponse = new RequestDTResponseMessage();
    dtResponse.token_type   = DT_TYPE;
    dtResponse.access_token = DT;
    dtResponse.expires_in   = BigInteger.valueOf(System.currentTimeMillis() + (10 * 60 * 1000));
    dtResponse.target_url   = null;

    // The soon-to-expire DT should trigger a request to update the DT
    EasyMock.expect(mockClient.updateDelegationToken(eq(DT), eq(DT_TYPE), anyString()))
            .andReturn(dtResponse);

    // The subsequent request to get GCP credentials using the updated DT should succeed
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
            .andReturn(testAccessToken);

    EasyMock.replay(mockClient);

    // Try getting an access token with a DT that has not yet expired but is about to expire
    invokeCloudAccessBrokerTokenProvider(mockClient, DT, DT_TYPE, DT_EXPIRES, CAB_URL, GCP_TOKEN, GCP_TOKEN_EXP);
  }


  /**
   * Test getting existing valid credentials with an expired delegation token.
   */
  @Test
  public void testGetCredentialsWithExpiredDT() throws Exception {
    final String CAB_URL =
        CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS + CloudAccessBrokerClientTestUtils.CAB_PATH;

    final String DT_TYPE       = "Bearer";
    final String DT            = "DELEGATION_TOKEN_DUMMY";
    final long   DT_EXPIRES    =  System.currentTimeMillis();
    final String GCP_TOKEN     = "GOOGLE_TOKEN_DUMMY";
    final Long   GCP_TOKEN_EXP = System.currentTimeMillis() + (60 * 1000); // now + 1 minute

    AccessTokenProvider.AccessToken testAccessToken = new AccessTokenProvider.AccessToken(GCP_TOKEN, GCP_TOKEN_EXP);

    IDBClient<AccessTokenProvider.AccessToken> mockClient = createIDBClientMock();
    EasyMock.expect(mockClient.cloudSessionFromDelegationToken(anyString(), eq("Bearer"))).andReturn(null);

    // There should be a request to refresh the expiring DT
    RequestDTResponseMessage dtResponse = new RequestDTResponseMessage();
    dtResponse.token_type   = DT_TYPE;
    dtResponse.access_token = DT;
    dtResponse.expires_in   = BigInteger.valueOf(System.currentTimeMillis() + (10 * 60 * 1000));
    dtResponse.target_url   = null;

    // Simulate the expired DT
    EasyMock.expect(mockClient.updateDelegationToken(eq(DT), eq(DT_TYPE), anyString()))
            .andThrow(new IOException("HTTP/1.1 400 Bad request: token has expired"));

    // Access token provider should attempt to establish a new DT session, and get a new DT
    Pair<KnoxSession, String> sessionTuple = new Pair<KnoxSession, String>() {
      @Override
      public KnoxSession getLeft() {
        return null;
      }

      @Override
      public String getRight() {
        return null;
      }

      @Override
      public String setValue(String value) {
        return null;
      }
    };
    EasyMock.expect(mockClient.login(anyObject())).andReturn(sessionTuple);
    EasyMock.expect(mockClient.requestKnoxDelegationToken(anyObject(KnoxSession.class),
                                                          anyString(),
                                                          anyObject(URI.class)))
            .andReturn(dtResponse);

    // The new DT should be used to make an attempt to get GCP credentials
    EasyMock.expect(mockClient.fetchCloudCredentials(anyObject(CloudAccessBrokerSession.class)))
            .andReturn(testAccessToken);

    EasyMock.replay(mockClient);

    // Try getting an access token with a DT that has expired
    invokeCloudAccessBrokerTokenProvider(mockClient, DT, DT_TYPE, DT_EXPIRES, CAB_URL, GCP_TOKEN, GCP_TOKEN_EXP);
  }


  // Internal test method
  private AccessTokenProvider.AccessToken invokeCloudAccessBrokerTokenProvider(final IDBClient<AccessTokenProvider.AccessToken> client,
                                                                               final String delegationToken,
                                                                               final String delegationTokenType,
                                                                               final long   delegationTokenExpiration,
                                                                               final String cabURL,
                                                                               final String gcpToken,
                                                                               final long   gcpTokenExpiration) {
    CloudAccessBrokerTokenProvider tp =
        new CloudAccessBrokerTokenProvider(client,
            delegationToken,
            delegationTokenType,
            cabURL,
            delegationTokenExpiration,
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

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
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.test.LambdaTestUtils;
import org.apache.knox.test.category.VerifyTest;

import org.junit.After;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@Category({VerifyTest.class})
public class CloudAccessBrokerTokenProviderTest {

  @After
  public void cleanup() {
    try {
      // Restore the token cache backup (if it exists) after every test
      CloudAccessBrokerClientTestUtils.restoreTokenCacheBackup();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


  /**
   * Test getting credentials from the default /credentials API, using knox init for CAB authentication
   */
  @Test
  public void testDefaultGetCredentials_KnoxInit() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set("cab.address", CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS);

    // Initialize the Knox token, since we're not specifying any DT-related configuration
    CloudAccessBrokerClientTestUtils.knoxInit();

    // The KnoxTokenCredentialCollector should find the Knox token, and use it for the interaction with the CAB to get
    // the GCP credentials
    AccessTokenProvider.AccessToken at = testGetAccessToken(conf);

    assertNotNull(at);
    assertNotNull(at.getToken());
    assertNotNull(at.getExpirationTimeMilliSeconds());
    assertTrue(at.getExpirationTimeMilliSeconds() > System.currentTimeMillis());
  }


  /**
   * Test getting credentials from the default /credentials API, with config for getting the delegation token prior to
   * the CAB interaction.
   */
  @Test
  public void testDefaultGetCredentials() throws Exception {

    // If there is a cached knox token, back it up
    CloudAccessBrokerClientTestUtils.backupTokenCache();

    // Delete the existing token cache, so the access token provider will request a new one based on the config
    CloudAccessBrokerClientTestUtils.deleteTokenCache();

    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS,
             CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS);

    // Add config for the delegation token request, since there is no valid token in the cache
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_DT_ADDRESS, CloudAccessBrokerClientTestUtils.DT_ADDRESS);

    AccessTokenProvider.AccessToken at = testGetAccessToken(conf);

    assertNotNull(at);
    assertNotNull(at.getToken());
    assertNotNull(at.getExpirationTimeMilliSeconds());
    assertTrue(at.getExpirationTimeMilliSeconds() > System.currentTimeMillis());
  }


  /**
   * Test getting credentials from the default /credentials API, with config for getting the delegation token prior to
   * the CAB interaction, but missing the DT address.
   */
  @Test
  public void testDefaultGetCredentials_MissingDTAddress() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set("cab.address", CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS);

    // Add config for the delegation token request, since there is no valid token in the cache
    conf.set("cab.dt.username", "admin");
    conf.set("cab.dt.pass", "admin-password");

    testDefaultGetCredentials_MissingDTConfig(conf);
  }


  /**
   * Test getting credentials from the default /credentials API, with config for getting the delegation token prior to
   * the CAB interaction, but missing the DT username.
   */
  @Test
  public void testDefaultGetCredentials_MissingDTUsername() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set("cab.address", CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS);

    // Add config for the delegation token request, since there is no valid token in the cache
    conf.set("delegation.token.address", CloudAccessBrokerClientTestUtils.DT_ADDRESS);
    conf.set("cab.dt.pass", "admin-password");

    testDefaultGetCredentials_MissingDTConfig(conf);
  }


  /**
   * Test getting credentials from the default /credentials API, with config for getting the delegation token prior to
   * the CAB interaction, but missing the DT password.
   */
  @Test
  public void testDefaultGetCredentials_MissingDTPass() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set("cab.address", CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS);

    // Add config for the delegation token request, since there is no valid token in the cache
    conf.set("delegation.token.address", CloudAccessBrokerClientTestUtils.DT_ADDRESS);
    conf.set("cab.dt.username", "admin");

    testDefaultGetCredentials_MissingDTConfig(conf);
  }


  /**
   * Test getting credentials from the default /credentials API, with the specified config (missing one or more items)
   * for getting the delegation token prior to the CAB interaction.
   */
  private void testDefaultGetCredentials_MissingDTConfig(Configuration config) throws Exception {
    // If there is a cached knox token, back it up
    CloudAccessBrokerClientTestUtils.backupTokenCache();

    // Delete the existing token cache, so the access token provider will request a new one based on the config
    CloudAccessBrokerClientTestUtils.deleteTokenCache();

    LambdaTestUtils.intercept(IllegalStateException.class,
        () -> testGetAccessToken(config));
  }


  @Test
  public void testGetDefaultGroupCredentials() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set("cab.address", CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS);
    conf.set("cab.prefer.group.role", "admin");

    // Initialize the Knox token
    CloudAccessBrokerClientTestUtils.knoxInit();

    AccessTokenProvider.AccessToken at = testGetAccessToken(conf);

    assertNotNull(at);
    assertNotNull(at.getToken());
    assertNotNull(at.getExpirationTimeMilliSeconds());
    assertTrue(at.getExpirationTimeMilliSeconds() > System.currentTimeMillis());
  }


  @Test
  public void testGetSpecificGroupCredentials() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set("cab.address", CloudAccessBrokerClientTestUtils.CLOUD_ACCESS_BROKER_ADDRESS);
    conf.set("cab.prefer.group.role", "true");
    conf.set("cab.preferred.role", "admin");

    // Initialize the Knox token
    CloudAccessBrokerClientTestUtils.knoxInit();

    AccessTokenProvider.AccessToken at = testGetAccessToken(conf);
    assertNull(at);
  }


  private AccessTokenProvider.AccessToken testGetAccessToken(Configuration conf) {
    CloudAccessBrokerTokenProvider atp = new CloudAccessBrokerTokenProvider();
    atp.setConf(conf);
    return atp.getAccessToken();
  }

}

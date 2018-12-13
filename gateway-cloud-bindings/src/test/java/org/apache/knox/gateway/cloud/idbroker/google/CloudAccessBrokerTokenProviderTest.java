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
import org.apache.hadoop.test.HadoopTestBase;
import org.apache.hadoop.test.LambdaTestUtils;
import org.apache.knox.gateway.shell.CredentialCollectionException;
import org.apache.knox.gateway.shell.KnoxTokenCredentialCollector;
import org.apache.knox.test.category.VerifyTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.*;
import static org.junit.Assume.assumeNotNull;


@Category(VerifyTest.class)
public class CloudAccessBrokerTokenProviderTest extends HadoopTestBase {

  protected static final Logger LOG =
      LoggerFactory.getLogger(CloudAccessBrokerTokenProviderTest.class);

  @Before
  public void setup() {
    assumeNotNull(System.getenv(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS.replace(".", "_")));
  }

  @After
  public void cleanup() {
    try {
      // Restore the token cache backup (if it exists) after every test
      CloudAccessBrokerClientTestUtils.restoreTokenCacheBackup();
    } catch (Exception e) {
      // only print the stack @ debug, to avoid logs being full of confusing
      // traces.
      LOG.info("While restoring backup: {}", e.toString());
      LOG.info("While restoring backup", e);
    }
  }


  /**
   * Test getting credentials from the default /credentials API without having initialized a delegation token
   */
  @Test
  public void testDefaultGetCredentialsMissingDelegationToken() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, CLOUD_ACCESS_BROKER_ADDRESS);
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_PATH, CAB_PATH);

    LambdaTestUtils.intercept(IllegalArgumentException.class,
        () -> testGetAccessToken(conf));
  }


  /**
   * Test getting credentials from the default /credentials API
   */
  @Test
  public void testDefaultGetCredentials() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, CLOUD_ACCESS_BROKER_ADDRESS);
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_PATH, CAB_PATH);

    // If there is a cached knox token, back it up
    CloudAccessBrokerClientTestUtils.backupTokenCache();

    // Delete the existing token cache
    CloudAccessBrokerClientTestUtils.deleteTokenCache();

    // Initialize the Knox delegation token
    knoxInit(TRUST_STORE_LOCATION, TRUST_STORE_PASS);

    AccessTokenProvider.AccessToken at = testGetAccessToken(conf);

    assertNotNull(at);
    assertNotNull(at.getToken());
    assertNotNull(at.getExpirationTimeMilliSeconds());
    assertTrue(at.getExpirationTimeMilliSeconds() > System.currentTimeMillis());
  }


  @Test
  public void testGetDefaultGroupCredentials() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, CLOUD_ACCESS_BROKER_ADDRESS);
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_PATH, CAB_PATH);
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_EMPLOY_GROUP_ROLE, "true");

    // If there is a cached knox token, back it up
    CloudAccessBrokerClientTestUtils.backupTokenCache();

    // Delete the existing token cache
    CloudAccessBrokerClientTestUtils.deleteTokenCache();

    // Initialize the Knox delegation token
    knoxInit(TRUST_STORE_LOCATION, TRUST_STORE_PASS);

    AccessTokenProvider.AccessToken at = testGetAccessToken(conf);

    assertNull("Unexpected access token for user with no group affiliations.", at);
  }


  @Test
  public void testGetSpecificGroupCredentials() throws Exception {
    // Configure the token provider
    Configuration conf = new Configuration();
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, CLOUD_ACCESS_BROKER_ADDRESS);
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_PATH, CAB_PATH);
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_REQUIRED_GROUP, "admin");

    // If there is a cached knox token, back it up
    CloudAccessBrokerClientTestUtils.backupTokenCache();

    // Delete the existing token cache
    CloudAccessBrokerClientTestUtils.deleteTokenCache();

    // Initialize the Knox delegation token
    knoxInit(TRUST_STORE_LOCATION, TRUST_STORE_PASS);

    AccessTokenProvider.AccessToken at = testGetAccessToken(conf);

    assertNull("Unexpected access token for user with unmatched group affiliations.", at);
  }


  private AccessTokenProvider.AccessToken testGetAccessToken(Configuration conf) {
    String dt       = null;
    String dtType   = null;
    String dtTarget = null;

    // Check for a delegation token in the Knox token cache
    try {
      KnoxTokenCredentialCollector collector = new KnoxTokenCredentialCollector();
      collector.collect();
      dt       = collector.string();
      dtType   = collector.getTokenType();
      dtTarget = collector.getTargetUrl();
    } catch (CredentialCollectionException e) {
      //
    }

    CloudAccessBrokerTokenProvider atp = new CloudAccessBrokerTokenProvider(dt, dtType, dtTarget);
    atp.setConf(conf);
    return atp.getAccessToken();
  }

}

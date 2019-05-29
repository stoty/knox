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

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.cloud.idbroker.common.CommonConstants;
import org.apache.knox.gateway.cloud.idbroker.common.DefaultRequestExecutor;
import org.apache.knox.gateway.cloud.idbroker.common.EndpointManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class GCPCABClientTest {

  private final Logger logger = Logger.getLogger("org.apache.knox.gateway.shell");

  private LogHandler logCapture;
  private Level originalLevel;

  @Before
  public void setUp() {
    originalLevel = logger.getLevel();
    logger.setLevel(Level.FINEST);
    logCapture = new LogHandler();
    logger.addHandler(logCapture);
  }

  @After
  public void tearDown() {
    logger.removeHandler(logCapture);
    logger.setLevel(originalLevel);
  }

  @Test
  public void testCreateClientWithoutEndpointConfiguration() {
    try {
      doTestCreateClientEndpointConfiguration(new String[0], null);
      fail("Expected an IllegalArgumentException because no CAB endpoints are configured.");
    } catch (IllegalStateException e) {
      assertEquals("At least one CloudAccessBroker endpoint must be configured.", e.getMessage());
    }
  }

  @Test
  public void testCreateClientWithSingleEndpointConfiguration() {
    final String[] endpoints = {"http://host1:8444/gateway/"};
    doTestCreateClientEndpointConfiguration(endpoints, null);
  }

  @Test
  public void testCreateClientWithMultipleEndpointConfiguration() {
    final String endpointDelimiter = ",";
    final String[] endpoints =
        {"http://host1:8444/gateway/", "http://host2:8444/gateway/", "http://host3:8444/gateway/"};
    doTestCreateClientEndpointConfiguration(endpoints, endpointDelimiter);
  }

  @Test
  public void testCreateClientWithMultipleEndpointConfigurationWithSpaces() {
    final String endpointDelimiter = ", ";
    final String[] endpoints =
        {"http://host1:8444/gateway/", "http://host2:8444/gateway/", "http://host3:8444/gateway/"};
    doTestCreateClientEndpointConfiguration(endpoints, endpointDelimiter);
  }

  /**
   *
   * @param endpoints The endpoints to include in the address configuration property value.
   * @param endpointDelimiter The delimiter to use between the endpoints.
   */
  private void doTestCreateClientEndpointConfiguration(final String[] endpoints, final String endpointDelimiter) {
    String endpointConfigValue = "";
    for (int i = 0; i < endpoints.length; i++) {
      endpointConfigValue += endpoints[i];
      if (i < endpoints.length - 1) {
        endpointConfigValue += endpointDelimiter;
      }
    }

    Configuration conf = new Configuration();
    if (!StringUtils.isBlank(endpointConfigValue)) {
      conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, endpointConfigValue);
    }

    GCPCABClient client = new GCPCABClient(conf);
    assertNotNull(client);
    validateClientEndpoints(client, endpoints);
  }

  /**
   *
   * @param client The client to validate.
   * @param expectedEndpoints The endpoints expected to have been configured for the client.
   */
  private void validateClientEndpoints(GCPCABClient client, String...expectedEndpoints) {
    EndpointManager em  = null;
    try {
      Field reqExecField = client.getClass().getDeclaredField("requestExecutor");
      reqExecField.setAccessible(true);
      DefaultRequestExecutor re = (DefaultRequestExecutor) reqExecField.get(client);
      assertNotNull(re);
      Field endpointMgrField = re.getClass().getDeclaredField("endpointManager");
      endpointMgrField.setAccessible(true);
      em = (EndpointManager) endpointMgrField.get(re);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      e.printStackTrace();
    }
    assertNotNull(em);
    List<String> endpoints = em.getURLs();
    assertEquals("The count of actual endpoints does not match the expected count.",
                 expectedEndpoints.length,
                 endpoints.size());
    for (String expectedEndpoint : expectedEndpoints) {
      assertTrue("Expected endpoint not included among actual endpoints.", endpoints.contains(expectedEndpoint));
    }
  }


  @Test
  public void testCreateKerberosDTSessionWithJAASConfOverride() {
    final String testJaasConf = "/etc/gcpcabclienttest-jaas.conf";

    Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host1:8444/gateway");
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_JAAS_FILE, testJaasConf);

    doInvokeCreateKerberosDTSession(conf);

    assertEquals(3, logCapture.messages.size());
    assertEquals("The specified JAAS configuration does not exist: " + testJaasConf, logCapture.messages.get(0));
    assertEquals("Using default JAAS configuration", logCapture.messages.get(1));
  }


  @Test
  public void testCreateKerberosDTSessionWithDefaultJAASConf() {
    Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host1:8444/gateway");

    // Test without the JAAS conf property set
    doInvokeCreateKerberosDTSession(conf);

    assertEquals(2, logCapture.messages.size());
    assertEquals("Using default JAAS configuration", logCapture.messages.get(0));
  }

  @Test
  public void testGCSConnectorOnlyTrustStoreConfig() {
    final String location = "my-test-truststore.jks";
    final String pass = "noneofyourbusiness";
    Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host:8444/gateway");
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_LOCATION, location);
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_PASS, pass);
    doTestTrustStoreConfig(conf, location, pass);
  }

  @Test
  public void testGCSConnectorAndAutoTLSTrustStoreConfig() {
    final String location = "my-test-truststore.jks";
    final String pass = "noneofyourbusiness";
    Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host:8444/gateway");
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_LOCATION, location);
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_PASS, pass);
    conf.set(CommonConstants.SSL_TRUSTSTORE_LOCATION, "auto-tls-truststore.jks");
    conf.set(CommonConstants.SSL_TRUSTSTORE_PASS, "auto-tls-truststore-pass");
    doTestTrustStoreConfig(conf, location, pass);
  }

  @Test
  public void testAutoTLSOnlyTrustStoreConfig() {
    final String location = "auto-tls-truststore.jks";
    final String pass = "auto-tls-truststore-pass";
    Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host:8444/gateway");
    conf.set(CommonConstants.SSL_TRUSTSTORE_LOCATION, location);
    conf.set(CommonConstants.SSL_TRUSTSTORE_PASS, pass);
    doTestTrustStoreConfig(conf, location, pass);
  }

  @Test
  public void testUseDTCertConfigDefault() {
    final Boolean expectedValue = Boolean.FALSE;
    final Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host:8444/gateway");
    doTestUseDTCertConfig(conf, expectedValue);
  }

  @Test
  public void testUseDTCertConfigTrue() {
    final Boolean expectedValue = Boolean.TRUE;
    final Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host:8444/gateway");
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_PREFIX + CommonConstants.USE_CERT_FROM_DT_SUFFIX, "true");
    doTestUseDTCertConfig(conf, expectedValue);
  }

  @Test
  public void testUseDTCertConfigFalse() {
    final Boolean expectedValue = Boolean.FALSE;
    final Configuration conf = new Configuration();
    CABUtils.setCloudAccessBrokerAddresses(conf, "https://host:8444/gateway");
    conf.set(CloudAccessBrokerBindingConstants.CONFIG_PREFIX + CommonConstants.USE_CERT_FROM_DT_SUFFIX, "false");
    doTestUseDTCertConfig(conf, expectedValue);
  }

  private void doTestUseDTCertConfig(final Configuration conf, final Boolean expectedValue) {
    GCPCABClient client = new GCPCABClient(conf);
    Boolean actualValue = null;
    try {
      Field useIDBCertificateFromDT = GCPCABClient.class.getDeclaredField("useIDBCertificateFromDT");
      useIDBCertificateFromDT.setAccessible(true);
      actualValue = (Boolean) useIDBCertificateFromDT.get(client);
    } catch (Exception e) {
      fail();
    }
    assertEquals(expectedValue, actualValue);
  }

  private void doTestTrustStoreConfig(Configuration conf, String expectedLocation, String expectedPass) {
    GCPCABClient client = new GCPCABClient(conf);
    assertEquals(expectedLocation, client.getTrustStoreLocation());
    assertEquals(expectedPass, client.getTrustStorePass());
  }

  private void doInvokeCreateKerberosDTSession(final Configuration conf) {
    try {
      (new GCPCABClient(conf)).createKerberosDTSession(null);
    } catch (URISyntaxException e) {
      fail(e.getMessage());
    }
  }


  private static class LogHandler extends Handler {
    final List<String> messages = new ArrayList<>();

    @Override
    public void publish(LogRecord record) {
      messages.add(record.getMessage());
    }

    @Override
    public void flush() {
    }

    @Override
    public void close() throws SecurityException {
    }
  }

}

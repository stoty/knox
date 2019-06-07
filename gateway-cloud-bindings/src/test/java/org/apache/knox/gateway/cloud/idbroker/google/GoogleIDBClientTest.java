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
import junit.framework.TestCase;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.knox.gateway.cloud.idbroker.AbstractIDBClient;
import org.apache.knox.gateway.cloud.idbroker.AbstractIDBClientTest;
import org.apache.knox.gateway.cloud.idbroker.IDBProperty;
import org.apache.knox.gateway.cloud.idbroker.common.CommonConstants;
import org.apache.knox.gateway.cloud.idbroker.common.DefaultRequestExecutor;
import org.apache.knox.gateway.cloud.idbroker.common.EndpointManager;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.test.category.UnitTests;
import org.easymock.IMockBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_ONLY_GROUPS_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_ONLY_USER_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_PATH;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_USE_DT_CERT;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_ONLY_GROUPS_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_ONLY_USER_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_SPECIFIC_GROUP_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_SPECIFIC_ROLE_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_USE_DT_CERT;
import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@Category(UnitTests.class)
public class GoogleIDBClientTest extends AbstractIDBClientTest {

  private static final String TEST_TOKEN =
      "ya29.c.EvUBGQc9KXO1R6t85lfanE7YIcMJnfo1Z9sIMtXbSWt8CliV_3HvA6MRo-qRs0t466V4wXYZi82JvnNj2S0eAISERP1w" +
      "fQuO7DWdbQy9ri64P7qsFgowIRYUgm0FgGMN1717ASeC8jvhkA_837I8n1c6vbNn1NsVzg_PT4EBcG-a84JV1Oq0-qEn56fu_SS" +
      "fBi_rx6ys_RRJyz2zqDfRbIJD1wn0E6ecOfiE-8vgJlZExwo_fjjVcb5z_8FOu2AgSk--e9tkX9KkyBjVHffQl6wcuaMbFGh15S" +
      "5kVJv342bdYfsn6e0Go97COiQ2S8ZaBh-1V2wikYQ";

  private static final String TEST_EXPIRATION = "2019-05-30T14:03:57Z";

  private static final String TEST_ACCESS_TOKEN_RESPONSE =
      "{\n" +
      "  \"accessToken\": \"" + TEST_TOKEN + "\",\n" +
      "  \"expireTime\": \"" + TEST_EXPIRATION + "\"\n" +
      "}\n";

  private static final Map<String, IDBProperty> PROPERTY_MAP;
  static {
    Map<String, IDBProperty> map = new HashMap<>();

    map.put(PROPERTY_SUFFIX_GATEWAY, IDBROKER_GATEWAY);
    map.put(PROPERTY_SUFFIX_USERNAME, IDBROKER_USERNAME);
    map.put(PROPERTY_SUFFIX_PASSWORD, IDBROKER_PASSWORD);
    map.put(PROPERTY_SUFFIX_TRUSTSTORE_LOCATION, IDBROKER_TRUSTSTORE_LOCATION);
    map.put(PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD, IDBROKER_TRUSTSTORE_PASSWORD);
    map.put(PROPERTY_SUFFIX_TRUSTSTORE_PASS, IDBROKER_TRUSTSTORE_PASS);
    map.put(PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD, IDBROKER_SPECIFIC_GROUP_METHOD);
    map.put(PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD, IDBROKER_SPECIFIC_ROLE_METHOD);
    map.put(PROPERTY_SUFFIX_ONLY_GROUPS_METHOD, IDBROKER_ONLY_GROUPS_METHOD);
    map.put(PROPERTY_SUFFIX_ONLY_USER_METHOD, IDBROKER_ONLY_USER_METHOD);
    map.put(PROPERTY_SUFFIX_PATH, IDBROKER_PATH);
    map.put(PROPERTY_SUFFIX_DT_PATH, IDBROKER_DT_PATH);
    map.put(PROPERTY_SUFFIX_CREDENTIALS_TYPE, IDBROKER_CREDENTIALS_TYPE);
    map.put(PROPERTY_SUFFIX_USE_DT_CERT, IDBROKER_USE_DT_CERT);

    PROPERTY_MAP = Collections.unmodifiableMap(map);
  }


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


  @Test
  public void testExtractCloudCredentialsFromResponse() throws IOException {
    UserGroupInformation owner = createMock(UserGroupInformation.class);

    BasicResponse response = createMock(BasicResponse.class);
    expect(response.getStatusCode()).andReturn(200).once();
    expect(response.getContentType()).andReturn("application/json").once();
    expect(response.getContentLength()).andReturn((long) TEST_ACCESS_TOKEN_RESPONSE.length()).once();
    expect(response.getString()).andReturn(TEST_ACCESS_TOKEN_RESPONSE).once();

    replayAll();

    Configuration conf = new Configuration();
    conf.set(IDBROKER_GATEWAY.getPropertyName(), IDBROKER_GATEWAY.getDefaultValue());
    conf.set(IDBROKER_PATH.getPropertyName(), IDBROKER_PATH.getDefaultValue());
    GoogleIDBClient client = new GoogleIDBClient(conf, owner);

    AccessTokenProvider.AccessToken credentials = client.extractCloudCredentialsFromResponse(response);
    assertNotNull(credentials);
    assertEquals(TEST_TOKEN, credentials.getToken());
    assertEquals(DateTime.parseRfc3339(TEST_EXPIRATION).getValue(), (long) credentials.getExpirationTimeMilliSeconds());

    verifyAll();
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

    GoogleIDBClient client = null;
    try {
      client = new GoogleIDBClient(conf, null);
    } catch (IOException e) {
      fail(e.getMessage());
    }
    TestCase.assertNotNull(client);
    validateClientEndpoints(client, endpoints);
  }

  /**
   *
   * @param client The client to validate.
   * @param expectedEndpoints The endpoints expected to have been configured for the client.
   */
  private void validateClientEndpoints(GoogleIDBClient client, String...expectedEndpoints) {
    EndpointManager em  = null;
    try {
      Field reqExecField = client.getClass().getSuperclass().getDeclaredField("requestExecutor");
      reqExecField.setAccessible(true);
      DefaultRequestExecutor re = (DefaultRequestExecutor) reqExecField.get(client);
      TestCase.assertNotNull(re);
      Field endpointMgrField = re.getClass().getDeclaredField("endpointManager");
      endpointMgrField.setAccessible(true);
      em = (EndpointManager) endpointMgrField.get(re);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      e.printStackTrace();
    }
    TestCase.assertNotNull(em);
    List<String> endpoints = em.getURLs();
    assertEquals("The count of actual endpoints does not match the expected count.",
        expectedEndpoints.length,
        endpoints.size());
    for (String expectedEndpoint : expectedEndpoints) {
      assertTrue("Expected endpoint not included among actual endpoints.", endpoints.contains(expectedEndpoint));
    }
  }

  private void doTestUseDTCertConfig(final Configuration conf, final Boolean expectedValue) {
    GoogleIDBClient client = null;
    try {
      client = new GoogleIDBClient(conf, null);
    } catch (IOException e) {
      fail(e.getMessage());
    }

    Boolean actualValue = null;
    try {
      Field useIDBCertificateFromDT =
          GoogleIDBClient.class.getSuperclass().getDeclaredField("useCertificateFromDT");
      useIDBCertificateFromDT.setAccessible(true);
      actualValue = (Boolean) useIDBCertificateFromDT.get(client);
    } catch (Exception e) {
      fail(e.getMessage());
    }
    assertEquals(expectedValue, actualValue);
  }

  private void doTestTrustStoreConfig(Configuration conf, String expectedLocation, String expectedPass) {
    final File testTrustStore = new File(expectedLocation);
    try {
      FileUtils.touch(testTrustStore);
    } catch (IOException e) {
      e.printStackTrace();
    }

    try {
      //    GCPCABClient client = new GCPCABClient(conf);
      GoogleIDBClient client = null;
      try {
        client = new GoogleIDBClient(conf, null);
      } catch (IOException e) {
        fail(e.getMessage());
      }
      assertEquals(expectedLocation, client.getTruststorePath());
      assertEquals(expectedPass, client.getTruststorePassword());
    } finally {
      testTrustStore.delete();
    }
  }

  private void doInvokeCreateKerberosDTSession(final Configuration conf) {
    try {
      (new GoogleIDBClient(conf, null)).knoxSessionFromKerberos();
    } catch (Exception e) {
      fail(e.getMessage());
    }
  }


  @Override
  protected IMockBuilder<? extends AbstractIDBClient> getIDBClientMockBuilder(Configuration configuration,
                                                                              UserGroupInformation owner) {
    return createMockBuilder(GoogleIDBClient.class).withConstructor(configuration, owner);
  }

  @Override
  protected Map<String, IDBProperty> getPropertyMap() {
    return PROPERTY_MAP;
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

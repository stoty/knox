/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.knox.gateway.cloud.idbroker;

import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDBROKER_CREDENTIALS_KERBEROS;
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
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_USE_DT_CERT;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBClient;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;
import org.easymock.EasyMockSupport;
import org.easymock.IMockBuilder;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Map;

public abstract class AbstractIDBClientTest extends EasyMockSupport {
  @Rule
  public final TemporaryFolder testFolder = new TemporaryFolder();

  @Test
  public void testGetProperties() throws IOException {
    File bogusTruststore = testFolder.newFile();

    String expectedGatewayBaseURL = "https://localhost:8443/testgateway/";
    String expectedTruststorePath = bogusTruststore.getPath();
    String expectedTruststorePassword = "tuststore_password";
    String expectedPath = "test-cab";
    String expectedDtPath = "test-dt";
    String expectedCredentialsType = IDBROKER_CREDENTIALS_KERBEROS;
    String expectedPassword = "login_password";
    String expectedUsername = "login_username";
    String expectedSpecificGroup = "group1";
    String expectedSpecificRole = "role1";
    String expectedGroupsOnly = "true";
    String expectedUserOnly = "true";
    String expectedUseDBCert = "true";

    UserGroupInformation owner = createMock(UserGroupInformation.class);

    Map<String, IDBProperty> propertyMap = getPropertyMap();

    Configuration configuration = new Configuration();
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_GATEWAY).getPropertyName(), expectedGatewayBaseURL);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_TRUSTSTORE_LOCATION).getPropertyName(), expectedTruststorePath);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_TRUSTSTORE_PASS).getPropertyName(), expectedTruststorePassword);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_PATH).getPropertyName(), expectedPath);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_DT_PATH).getPropertyName(), expectedDtPath);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_CREDENTIALS_TYPE).getPropertyName(), expectedCredentialsType);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_PASSWORD).getPropertyName(), expectedPassword);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_USERNAME).getPropertyName(), expectedUsername);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD).getPropertyName(), expectedSpecificGroup);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD).getPropertyName(), expectedSpecificRole);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_GROUPS_METHOD).getPropertyName(), expectedGroupsOnly);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_USER_METHOD).getPropertyName(), expectedUserOnly);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_USE_DT_CERT).getPropertyName(), expectedUseDBCert);

    AbstractIDBClient client = getIDBClientMockBuilder(configuration, owner).createMock();

    replayAll();

    assertEquals(expectedGatewayBaseURL, client.getGatewayAddress());
    assertEquals(expectedTruststorePath, client.getTruststorePath(configuration));
    assertEquals(expectedTruststorePassword, String.valueOf(client.getTruststorePassword(configuration)));
    assertEquals(expectedGatewayBaseURL + expectedPath, client.getCredentialsURL(configuration));
    assertEquals(expectedGatewayBaseURL + expectedDtPath, client.getDelegationTokensURL(configuration));
    assertEquals(expectedCredentialsType, client.getCredentialsType(configuration));
    assertEquals(expectedPassword, client.getPassword(configuration));
    assertEquals(expectedUsername, client.getUsername(configuration));
    assertEquals(expectedSpecificGroup, client.getSpecificGroup(configuration));
    assertEquals(expectedSpecificRole, client.getSpecificRole(configuration));
    assertTrue(client.getOnlyGroups(configuration));
    assertTrue(client.getOnlyUser(configuration));
    assertTrue(client.getUseCertificateFromDT(configuration));

    assertEquals(propertyMap.get(PROPERTY_SUFFIX_PASSWORD).getPropertyName(), client.getPasswordPropertyName());
    assertEquals(propertyMap.get(PROPERTY_SUFFIX_USERNAME).getPropertyName(), client.getUsernamePropertyName());
    assertEquals(expectedGatewayBaseURL, client.getGatewayAddress());
    assertEquals(expectedTruststorePath, client.getTruststorePath());
    assertEquals(expectedTruststorePassword, client.getTruststorePassword());
    assertEquals(expectedGatewayBaseURL + expectedPath, client.getCredentialsURL());
    assertEquals(expectedGatewayBaseURL + expectedDtPath, client.getIdbTokensURL());

    verifyAll();
  }


  /**
   * Verify that the requestKnoxDelegationToken method will attempt re-login of the UGI prior to requesting the DT,
   * when the user was authenticated via Kerberos.
   */
  @Test
  public void testReloginWithKerberosFromRequestKnoxDelegationToken() throws Exception {
    final String EXPECTED_EXCEPTION_MSG = "IntendedExceptionForTest";

    CloudAccessBrokerSession mockedKnoxSession = createMock(CloudAccessBrokerSession.class);
    expect(mockedKnoxSession.base()).andReturn("http://localhost:8443/gateway").anyTimes();

    UserGroupInformation owner = createMock(UserGroupInformation.class);
    expect(owner.hasKerberosCredentials()).andReturn(true).once();
    expect(owner.isFromKeytab()).andReturn(true).anyTimes();
    // Just throw an exception from the code we're trying to verify here, to minimize the amount of mocking necessary
    owner.checkTGTAndReloginFromKeytab();
    expectLastCall().andThrow(new IOException(EXPECTED_EXCEPTION_MSG)).once();

    Map<String, IDBProperty> propertyMap = getPropertyMap();
    Configuration configuration = new Configuration();
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_CREDENTIALS_TYPE).getPropertyName(), IDBROKER_CREDENTIALS_KERBEROS);
    configuration.set(IDBConstants.HADOOP_SECURITY_AUTHENTICATION, IDBConstants.HADOOP_AUTH_KERBEROS);

    replayAll();

    AbstractIDBClient client = S3AIDBClient.createFullIDBClient(configuration, owner);

    try {
      client.requestKnoxDelegationToken(mockedKnoxSession, "test", new URI("s3a://whatever/"));
    } catch (IOException e) {
      // If the UGI#checkTGTAndReloginFromKeytab method gets called, then we should get the expected exception
      if (!e.getMessage().contains(EXPECTED_EXCEPTION_MSG)) {
        fail("Unexpected exception: " + e.getMessage());
      }
    }

    verifyAll();
  }

  @Test
  public void testLoginWithKerberos() throws IOException, InterruptedException {

    KnoxSession mockedKnoxSession = createMock(KnoxSession.class);

    UserGroupInformation owner = createMock(UserGroupInformation.class);
    expect(owner.hasKerberosCredentials()).andReturn(true).once();
    expect(owner.doAs(anyObject(PrivilegedExceptionAction.class))).andReturn(mockedKnoxSession).once();

    Map<String, IDBProperty> propertyMap = getPropertyMap();
    Configuration configuration = new Configuration();
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_CREDENTIALS_TYPE).getPropertyName(), IDBROKER_CREDENTIALS_KERBEROS);
    configuration.set(IDBConstants.HADOOP_SECURITY_AUTHENTICATION, IDBConstants.HADOOP_AUTH_KERBEROS);

    AbstractIDBClient client = getIDBClientMockBuilder(configuration, owner)
        .addMockedMethod("createKnoxDTSession", String.class, String.class)
        .createMock();

    replayAll();

    Pair value = client.createKnoxDTSession(configuration);
    assertNotNull(value);
    assertEquals("local kerberos", value.getValue());
    assertSame(mockedKnoxSession, value.getKey());

    verifyAll();
  }

  @Test
  public void testLoginWithBasicAuth() throws IOException {
    String expectedPassword = "login_password";
    String expectedUsername = "login_username";

    UserGroupInformation owner = createMock(UserGroupInformation.class);
    KnoxSession mockedKnoxSession = createMock(KnoxSession.class);

    Map<String, IDBProperty> propertyMap = getPropertyMap();
    Configuration configuration = new Configuration();
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_CREDENTIALS_TYPE).getPropertyName(), IDBROKER_CREDENTIALS_KERBEROS);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_PASSWORD).getPropertyName(), expectedPassword);
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_USERNAME).getPropertyName(), expectedUsername);
    configuration.set(IDBConstants.HADOOP_SECURITY_AUTHENTICATION, IDBConstants.HADOOP_AUTH_SIMPLE);

    AbstractIDBClient client = getIDBClientMockBuilder(configuration, owner)
        .addMockedMethod("createKnoxDTSession", String.class, String.class)
        .createMock();

    expect(client.createKnoxDTSession(eq(expectedUsername), eq(expectedPassword))).andReturn(mockedKnoxSession).once();

    replayAll();

    Pair value = client.createKnoxDTSession(configuration);
    assertNotNull(value);
    assertEquals("local credentials", value.getValue());
    assertSame(mockedKnoxSession, value.getKey());

    verifyAll();
  }

  @Test
  public void testDetermineIDBMethodToCall() throws IOException {

    Map<String, IDBProperty> propertyMap = getPropertyMap();

    for (IDBClient.IDBMethod method : IDBClient.IDBMethod.values()) {
      Configuration configuration = new Configuration();

      switch (method) {
        case SPECIFIC_ROLE:
          configuration.set(propertyMap.get(PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD).getPropertyName(), "specific_role");
        case USER_ONLY:
          configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_USER_METHOD).getPropertyName(), "true");
        case SPECIFIC_GROUP:
          configuration.set(propertyMap.get(PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD).getPropertyName(), "specific_group");
        case GROUPS_ONLY:
          configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_GROUPS_METHOD).getPropertyName(), "true");
        case DEFAULT:
          break;
      }

      testDetermineIDBMethodToCall(configuration, method);
      resetAll();
    }
  }

  /**
   * If ALL of the role selection algorithm configuration options are set, the PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD
   * should be applied since it is the most specific.
   */
  @Test
  public void testConflictingAlgorithmConfigurationAll() throws IOException {

    Map<String, IDBProperty> propertyMap = getPropertyMap();

    Configuration configuration = new Configuration();
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_GROUPS_METHOD).getPropertyName(), "true");
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_USER_METHOD).getPropertyName(), "true");
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD).getPropertyName(), "test_role");
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD).getPropertyName(), "qe_group");

    testDetermineIDBMethodToCall(configuration, IDBClient.IDBMethod.SPECIFIC_ROLE);
    resetAll();
  }

  /**
   * If all of PROPERTY_SUFFIX_ONLY_GROUPS_METHOD, PROPERTY_SUFFIX_ONLY_USER_METHOD, and
   * PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD config properties are set, then the most specific one
   * (PROPERTY_SUFFIX_ONLY_USER_METHOD) should be applied.
   */
  @Test
  public void testConflictingAlgorithmConfigurationUserAndGroupsAndSpecificGroup() throws IOException {

    Map<String, IDBProperty> propertyMap = getPropertyMap();

    Configuration configuration = new Configuration();
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_GROUPS_METHOD).getPropertyName(), "true");
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_USER_METHOD).getPropertyName(), "true");
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD).getPropertyName(), "qe_group");

    testDetermineIDBMethodToCall(configuration, IDBClient.IDBMethod.USER_ONLY);
    resetAll();
  }

  /**
   * If both the PROPERTY_SUFFIX_ONLY_GROUPS_METHOD and PROPERTY_SUFFIX_ONLY_USER_METHOD config properties are set to
   * true, then the most specific one (PROPERTY_SUFFIX_ONLY_USER_METHOD) should be applied.
   */
  @Test
  public void testConflictingAlgorithmConfigurationUserAndGroupPreference() throws IOException {

    Map<String, IDBProperty> propertyMap = getPropertyMap();

    Configuration configuration = new Configuration();
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_GROUPS_METHOD).getPropertyName(), "true");
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_USER_METHOD).getPropertyName(), "true");

    testDetermineIDBMethodToCall(configuration, IDBClient.IDBMethod.USER_ONLY);
    resetAll();
  }

  /**
   * If both PROPERTY_SUFFIX_ONLY_GROUPS_METHOD and PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD config properties are set,
   * then the most specific one (PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD) should be applied.
   */
  @Test
  public void testConflictingAlgorithmConfigurationGroupsAndSpecificGroup() throws IOException {

    Map<String, IDBProperty> propertyMap = getPropertyMap();

    Configuration configuration = new Configuration();
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_ONLY_GROUPS_METHOD).getPropertyName(), "true");
    configuration.set(propertyMap.get(PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD).getPropertyName(), "qe_group");

    testDetermineIDBMethodToCall(configuration, IDBClient.IDBMethod.SPECIFIC_GROUP);
    resetAll();
  }


  @Test
  public void testBuildUrl() throws IOException {

    UserGroupInformation owner = createMock(UserGroupInformation.class);
    AbstractIDBClient client = getIDBClientMockBuilder(new Configuration(), owner).createMock();

    replayAll();

    assertEquals("http://localhost/path", client.buildUrl("http://localhost/", "path"));
    assertEquals("http://localhost/path", client.buildUrl("http://localhost/", "/path"));
    assertEquals("http://localhost/path", client.buildUrl("http://localhost", "/path"));
    assertEquals("http://localhost/path", client.buildUrl("http://localhost", "path"));

    assertEquals("http://localhost:8080/path", client.buildUrl("http://localhost:8080/", "path"));
    assertEquals("http://localhost:8080/path", client.buildUrl("http://localhost:8080/", "/path"));
    assertEquals("http://localhost:8080/path", client.buildUrl("http://localhost:8080", "/path"));
    assertEquals("http://localhost:8080/path", client.buildUrl("http://localhost:8080", "path"));

    assertEquals("https://localhost/path", client.buildUrl("https://localhost/", "path"));
    assertEquals("https://localhost/path", client.buildUrl("https://localhost/", "/path"));
    assertEquals("https://localhost/path", client.buildUrl("https://localhost", "/path"));
    assertEquals("https://localhost/path", client.buildUrl("https://localhost", "path"));

    verifyAll();
  }

  @Test
  public void translateException() {
  }

  @Test
  public void processGet() {
  }

  @Test
  public void getPropertyValue() throws IOException {
    Configuration configuration = new Configuration();
    IDBProperty property1 = new IDBProperty() {
      @Override
      public String getPropertyName() {
        return "test_property_1";
      }

      @Override
      public String getDefaultValue() {
        return "default_value ";  // The trailing space is there on purpose, to test trimming
      }
    };

    IDBProperty property2 = new IDBProperty() {
      @Override
      public String getPropertyName() {
        return "test_property_2";
      }

      @Override
      public String getDefaultValue() {
        return null;
      }
    };

    UserGroupInformation owner = createMock(UserGroupInformation.class);
    AbstractIDBClient client = getIDBClientMockBuilder(configuration, owner).createMock();

    replayAll();

    assertEquals("default_value ", client.getPropertyValue(configuration, property1, false));
    assertEquals("default_value ", client.getPropertyValue(configuration, property1, true)); // The default value is not trimmed by Configuration
    assertNull(client.getPropertyValue(configuration, property2, false));
    assertNull(client.getPropertyValue(configuration, property2, true));

    configuration.set(property1.getPropertyName(), "some value");
    assertEquals("some value", client.getPropertyValue(configuration, property1, false));
    assertEquals("some value", client.getPropertyValue(configuration, property1, true));

    configuration.set(property1.getPropertyName(), " some value ");
    assertEquals(" some value ", client.getPropertyValue(configuration, property1, false));
    assertEquals("some value", client.getPropertyValue(configuration, property1, true));

    verifyAll();
  }

  /**
   * CDPD-17875
   */
  @Test
  public void getExplicitlyEmptyPropertyValue() throws IOException {
    Configuration configuration = new Configuration();
    IDBProperty property1 = new IDBProperty() {
      @Override
      public String getPropertyName() {
        return "test_property_1";
      }

      @Override
      public String getDefaultValue() {
        return "default_value";
      }
    };

    UserGroupInformation owner = createMock(UserGroupInformation.class);
    AbstractIDBClient client = getIDBClientMockBuilder(configuration, owner).createMock();

    replayAll();

    // Make sure the default value is returned when the property is not set at all
    assertEquals("default_value", client.getPropertyValue(configuration, property1, false));
    assertEquals("default_value", client.getPropertyValue(configuration, property1, true));

    // Make sure the default value is returned when the property is set to an empty value
    configuration.set(property1.getPropertyName(), "");
    assertEquals("default_value", client.getPropertyValue(configuration, property1, false));
    assertEquals("default_value", client.getPropertyValue(configuration, property1, true));

    verifyAll();
  }

  @Test
  public void getPropertyValueAsBoolean() throws IOException {
    Configuration configuration = new Configuration();

    IDBProperty property1 = createMock(IDBProperty.class);
    expect(property1.getPropertyName()).andReturn("test_property_1").anyTimes();
    expect(property1.getDefaultValue()).andReturn("default_value ").anyTimes(); // The trailing space is there on purpose, to test trimming

    IDBProperty property2 = createMock(IDBProperty.class);
    expect(property2.getPropertyName()).andReturn("test_property_2").anyTimes();
    expect(property2.getDefaultValue()).andReturn("true").anyTimes();

    IDBProperty property3 = createMock(IDBProperty.class);
    expect(property3.getPropertyName()).andReturn("test_property_3").anyTimes();
    expect(property3.getDefaultValue()).andReturn(null).anyTimes();

    IDBProperty property4 = createMock(IDBProperty.class);
    expect(property4.getPropertyName()).andReturn("test_property_4").anyTimes();
    expect(property4.getDefaultValue()).andReturn("true ").anyTimes(); // The trailing space is there on purpose, to test trimming

    UserGroupInformation owner = createMock(UserGroupInformation.class);
    AbstractIDBClient client = getIDBClientMockBuilder(configuration, owner).createMock();

    replayAll();

    assertFalse(client.getPropertyValueAsBoolean(configuration, property1));
    assertTrue(client.getPropertyValueAsBoolean(configuration, property2));
    assertFalse(client.getPropertyValueAsBoolean(configuration, property3));
    assertFalse(client.getPropertyValueAsBoolean(configuration, property4));

    configuration.set(property1.getPropertyName(), "some value");
    assertFalse(client.getPropertyValueAsBoolean(configuration, property1));

    configuration.set(property1.getPropertyName(), " true ");
    assertTrue(client.getPropertyValueAsBoolean(configuration, property1));

    configuration.set(property1.getPropertyName(), "true");
    assertTrue(client.getPropertyValueAsBoolean(configuration, property1));

    verifyAll();
  }

  @Test
  public void testSessionUnsupportedOperationException() throws IOException {
    Configuration configuration = new Configuration();
    UserGroupInformation owner = createMock(UserGroupInformation.class);
    AbstractIDBClient client = getIDBClientMockBuilder(configuration, owner).createMock();
    CloudAccessBrokerSession cab = client.createKnoxCABSession("test", "");
    Assert.assertNotNull(cab.getHeaders());
    cab.getHeaders().put("key","value");
  }

  protected abstract IMockBuilder<? extends AbstractIDBClient> getIDBClientMockBuilder(Configuration configuration,
                                                                                       UserGroupInformation owner)
      throws IOException;

  protected abstract Map<String, IDBProperty> getPropertyMap();

  private void testDetermineIDBMethodToCall(Configuration configuration, IDBClient.IDBMethod expectedMethod) throws IOException {
    UserGroupInformation owner = createMock(UserGroupInformation.class);
    AbstractIDBClient client = getIDBClientMockBuilder(configuration, owner).createMock();

    replayAll();
    assertEquals(expectedMethod, client.determineIDBMethodToCall());
    verifyAll();
  }

}

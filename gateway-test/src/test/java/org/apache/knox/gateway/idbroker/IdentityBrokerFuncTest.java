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
package org.apache.knox.gateway.idbroker;

import io.restassured.response.Response;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpStatus;
import org.apache.knox.gateway.GatewayServer;
import org.apache.knox.gateway.GatewayTestConfig;
import org.apache.knox.gateway.GatewayTestDriver;
import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.services.DefaultGatewayServices;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.util.JsonUtils;
import org.apache.log4j.Appender;
import org.hamcrest.MatcherAssert;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertEquals;

public class IdentityBrokerFuncTest {

  private static final String AWS_CAB_TOPOLOGY = "aws-cab";
  private static final String GCP_CAB_TOPOLOGY = "gcp-cab";

  private static Logger LOG = LoggerFactory.getLogger( IdentityBrokerFuncTest.class );

  private static GatewayTestDriver driver = new GatewayTestDriver();

  public static Enumeration<Appender> appenders;
  public static GatewayConfig config;
  public static GatewayServer gateway;
  public static String gatewayUrl;

  private static String currentTopology = AWS_CAB_TOPOLOGY;


  @BeforeClass
  public static void setupSuite() throws Exception {
    driver.setupLdap(0);
    setupGateway(new GatewayTestConfig());
  }

  @AfterClass
  public static void cleanupSuite() throws Exception {
    gateway.stop();
    driver.cleanup();
  }

  public static void setupGateway(GatewayTestConfig testConfig) throws Exception {

    File targetDir = new File( System.getProperty( "user.dir" ), "target" );
    File gatewayDir = new File( targetDir, "gateway-home-" + UUID.randomUUID() );
    gatewayDir.mkdirs();

    config = testConfig;
    testConfig.setGatewayHomeDir( gatewayDir.getAbsolutePath() );

    File topoDir = new File( testConfig.getGatewayTopologyDir() );
    topoDir.mkdirs();

    File deployDir = new File( testConfig.getGatewayDeploymentDir() );
    deployDir.mkdirs();

    File providerConfigDir = new File(testConfig.getGatewayProvidersConfigDir());
    providerConfigDir.mkdirs();

    File descriptorsDir = new File(testConfig.getGatewayDescriptorsDir());
    descriptorsDir.mkdirs();

    File providerConfig = new File(providerConfigDir, "test-providers.json");
    FileUtils.write(providerConfig, createProviderConfiguration(), StandardCharsets.UTF_8);

    File awsCABDescriptor = new File(descriptorsDir, AWS_CAB_TOPOLOGY + ".json");
    FileUtils.write(awsCABDescriptor, createAWSDescriptor("test-providers"), StandardCharsets.UTF_8);

    File gcpCABDescriptor = new File(descriptorsDir, GCP_CAB_TOPOLOGY + ".json");
    FileUtils.write(gcpCABDescriptor, createGCPDescriptor("test-providers"), StandardCharsets.UTF_8);

    DefaultGatewayServices srvcs = new DefaultGatewayServices();
    Map<String,String> options = new HashMap<>();
    options.put( "persist-master", "false" );
    options.put( "master", "password" );

    try {
      srvcs.init( testConfig, options );
    } catch ( ServiceLifecycleException e ) {
      e.printStackTrace(); // I18N not required.
    }

    gateway = GatewayServer.startGateway( testConfig, srvcs );
    MatcherAssert.assertThat( "Failed to start gateway.", gateway, notNullValue() );

    LOG.info( "Gateway port = " + gateway.getAddresses()[ 0 ].getPort() );

    gatewayUrl = "http://localhost:" + gateway.getAddresses()[0].getPort() + "/" + config.getGatewayPath();

    TestAWSCloudCredentialsClient.setRoleCredential("s3readonly", "TEST_S3READONLY_ROLE_TOKEN");
    TestAWSCloudCredentialsClient.setRoleCredential("s3full", "TEST_S3FULL_ROLE_TOKEN");
    TestAWSCloudCredentialsClient.setRoleCredential("s3audit", "TEST_S3AUDIT_ROLE_TOKEN");
    TestAWSCloudCredentialsClient.setRoleCredential("s3superduper", "TEST_S3SUPER_ROLE_TOKEN");
  }

  private static String createProviderConfiguration() {
    // This is a hard-coded string because the ShiroProvider param order is critically important
    return "{\n" +
           "  \"providers\": [\n" +
           "    {\n" +
           "      \"role\": \"authentication\",\n" +
           "      \"name\": \"ShiroProvider\",\n" +
           "      \"enabled\": \"true\",\n" +
           "      \"params\": {\n" +
           "        \"sessionTimeout\": \"20\",\n" +
           "        \"main.ldapRealm\": \"org.apache.knox.gateway.shirorealm.KnoxLdapRealm\",\n" +
           "        \"main.ldapContextFactory\": \"org.apache.knox.gateway.shirorealm.KnoxLdapContextFactory\",\n" +
           "        \"main.ldapRealm.contextFactory\": \"$ldapContextFactory\",\n" +
           "        \"main.ldapRealm.userDnTemplate\": \"uid={0},ou=people,dc=hadoop,dc=apache,dc=org\",\n" +
           "        \"main.ldapRealm.contextFactory.url\": \"ldap://localhost:33389\",\n" +
           "        \"main.ldapRealm.contextFactory.authenticationMechanism\": \"simple\",\n" +
           "        \"urls./**\": \"authcBasic\"\n" +
           "      }\n" +
           "    },\n" +
           "    {\n" +
           "      \"role\": \"identity-assertion\",\n" +
           "      \"name\": \"Pseudo\",\n" +
           "      \"enabled\": \"true\",\n" +
           "      \"params\": {\n" +
           "        \"group.principal.mapping\": \"admin=admin;guest=guest;sam=audit\"\n" +
           "      }\n" +
           "    }\n" +
           "  ]\n" +
           "}";
  }

  private static String createAWSDescriptor(String providerConfigRef) {
    Map<String, String> params = new HashMap<>();
    params.put("cloud.policy.config.provider", "default");
    params.put("cloud.client.provider", TestAWSCloudCredentialsClient.NAME);

    // role mappings
    params.put("role.user.guest", "s3readonly");
    params.put("role.user.admin", "s3superduper");
    params.put("role.group.admin", "s3full");
    params.put("role.group.audit", "s3audit");

    return createDescriptor(providerConfigRef, params);
  }


  private static String createGCPDescriptor(String providerConfigRef) {
    Map<String, String> params = new HashMap<>();
    params.put("cloud.policy.config.provider", "default");
    params.put("cloud.client.provider", "GCP");

    // role mappings
    params.put("role.user.guest", "storage-read-only@idbroker.iam.gserviceaccount.com");
    params.put("role.user.admin", "storage-admin@idbroker.iam.gserviceaccount.com");
    params.put("role.group.admin", "storage-admin@idbroker.iam.gserviceaccount.com");
    params.put("role.group.audit", "storage-audit@idbroker.iam.gserviceaccount.com");

    return createDescriptor(providerConfigRef, params);
  }


  private static String createDescriptor(String providerConfigRef, Map<String, String> idbParams) {
    Map<String, Object> descriptorModel = new HashMap<>();

    descriptorModel.put("provider-config-ref", providerConfigRef);

    List<Map<String, Object>> servicesModel = new ArrayList<>();

    Map<String, Object> idbServiceModel = new HashMap<>();
    idbServiceModel.put("name", "IDBROKER");
    idbServiceModel.put("params", idbParams);
    servicesModel.add(idbServiceModel);

    descriptorModel.put("services", servicesModel);

    return JsonUtils.renderAsJsonString(descriptorModel);
  }

  @Test
  public void testDefaultAPI_UnauthenticatedUser() {
    testDefaultCredentialAPI("joe", "public", HttpStatus.SC_UNAUTHORIZED);
  }

  @Test
  public void testDefaultAPI_AuthenticatedUser_NoRoleMapping() {
    testDefaultCredentialAPI("tom", "tom-password", HttpStatus.SC_FORBIDDEN);
  }

  @Test
  public void testDefaultAPI_AuthenticatedUser_DefaultRoleMapping() {
    Response response = testDefaultCredentialAPI("sam", "sam-password", HttpStatus.SC_OK);
    String responseBody = response.getBody().prettyPrint();
    assertEquals(TestAWSCloudCredentialsClient.getRoleCredential("s3audit"), responseBody);
  }

  /**
   * Verify that the default credentials request for an authenticated user (for whom there are both valid user and group
   * mappings) results in the credentials for the role associated with the user mapping.
   */
  @Test
  public void testDefaultAPI_AuthenticatedUser_DefaultRoleMapping_UserPriority() {
    Response response = testDefaultCredentialAPI("admin", "admin-password", HttpStatus.SC_OK);
    String responseBody = response.getBody().prettyPrint();
    assertEquals(TestAWSCloudCredentialsClient.getRoleCredential("s3superduper"), responseBody);
  }

  @Test
  public void testUserAPI_UnauthenticatedUser() {
    testUserCredentialAPI("joe", "public", HttpStatus.SC_UNAUTHORIZED);
  }

  /**
   * Verify that client is NOT permitted to assume a role for an authenticated user, for which there are no user or
   * group role mappings.
   */
  @Test
  public void testUserAPI_AuthenticatedUser_NoRoleMapping() {
    testUserCredentialAPI("tom", "tom-password", HttpStatus.SC_FORBIDDEN);
  }

  /**
   * Verify that client is permitted to assume a role for an authenticated user, for whom there is a user role mapping.
   */
    @Test
  public void testUserAPI_AuthenticatedUser_UserRoleMapping() {
    Response response = testUserCredentialAPI("guest", "guest-password", HttpStatus.SC_OK);
    String responseBody = response.getBody().prettyPrint();
    assertEquals(TestAWSCloudCredentialsClient.getRoleCredential("s3readonly"), responseBody);
  }

  /**
   * Verify that the user credentials request for an authenticated user (for whom there are both valid user and group
   * mappings) results in the credentials for the role associated with the user mapping.
   */
  @Test
  public void testUserAPI_AuthenticatedUser_RoleMapping_User() {
    Response response = testUserCredentialAPI("admin", "admin-password", HttpStatus.SC_OK);
    String responseBody = response.getBody().prettyPrint();
    assertEquals(TestAWSCloudCredentialsClient.getRoleCredential("s3superduper"), responseBody);
  }

  @Test
  public void testGroupAPI_UnauthenticatedUser() {
    testGroupCredentialAPI("joe", "public", HttpStatus.SC_UNAUTHORIZED);
  }

  @Test
  public void testGroupAPI_AuthenticatedUser_NoGroup() {
    testGroupCredentialAPI("tom", "tom-password", HttpStatus.SC_FORBIDDEN);
  }

  @Test
  public void testGroupAPI_AuthenticatedUser_GroupMapping() {
    Response response = testGroupCredentialAPI("sam", "sam-password", HttpStatus.SC_OK);
    String responseBody = response.getBody().prettyPrint();
    assertEquals(TestAWSCloudCredentialsClient.getRoleCredential("s3audit"), responseBody);
  }

  /**
   * Verify that the user credentials request for an authenticated user (for whom there are both valid user and group
   * mappings) results in the credentials for the role associated with the group mapping.
   */
  @Test
  public void testGroupAPI_AuthenticatedUser_RoleMapping_Group() {
    Response response = testGroupCredentialAPI("admin", "admin-password", HttpStatus.SC_OK);
    String responseBody = response.getBody().prettyPrint();
    assertEquals(TestAWSCloudCredentialsClient.getRoleCredential("s3full"), responseBody);
  }

  @Test
  public void testFilteredGroupAPI_UnauthenticatedUser() {
    testFilteredGroupCredentialAPI("admin", "joe", "public", HttpStatus.SC_UNAUTHORIZED);
  }

  /**
   * Verify that client is NOT permitted to assume a role for a group when the authenticated user has no associated
   * groups.
   */
  @Test
  public void testFilteredGroupAPI_AuthenticatedUser_NoGroup() {
    testFilteredGroupCredentialAPI("audit", "tom", "tom-password", HttpStatus.SC_FORBIDDEN);
  }

  /**
   * Verify that client is NOT permitted to assume a role for a group to which the authenticated user does not belong.
   */
  @Test
  public void testFilteredGroupAPI_AuthenticatedUser_Group_NoRoleMapping() {
    testFilteredGroupCredentialAPI("test", "sam", "sam-password", HttpStatus.SC_FORBIDDEN);
  }

  /**
   * Verify that client is permitted to assume a role for a specific group to which the authenticated user does belong.
   */
  @Test
  public void testFilteredGroupAPI_AuthenticatedUser_Group_RoleMapping() {
    Response response = testFilteredGroupCredentialAPI("audit", "sam", "sam-password", HttpStatus.SC_OK);
    String responseBody = response.getBody().prettyPrint();
    assertEquals(TestAWSCloudCredentialsClient.getRoleCredential("s3audit"), responseBody);
  }

  /**
   * Verify that the user credentials request for an authenticated user (for whom there are both valid user and group
   * mappings) results in the credentials for the role associated with the group mapping.
   */
  @Test
  public void testFilteredGroupAPI_AuthenticatedUser_RoleMapping_Group() {
    Response response = testFilteredGroupCredentialAPI("admin", "admin", "admin-password", HttpStatus.SC_OK);
    String responseBody = response.getBody().prettyPrint();
    assertEquals(TestAWSCloudCredentialsClient.getRoleCredential("s3full"), responseBody);
  }

  private Response testDefaultCredentialAPI(String username, String password, int expectedStatus) {
    final String serviceUrl = gatewayUrl + "/" + currentTopology + "/cab/api/v1/credentials";
    return testCredentialAPI(serviceUrl, username, password, expectedStatus);
  }

  private Response testUserCredentialAPI(String username, String password, int expectedStatus) {
    final String serviceUrl = gatewayUrl + "/" + currentTopology + "/cab/api/v1/credentials/user";
    return testCredentialAPI(serviceUrl, username, password, expectedStatus);
  }

  private Response testGroupCredentialAPI(String username, String password, int expectedStatus) {
    final String serviceUrl = gatewayUrl + "/" + currentTopology + "/cab/api/v1/credentials/group";
    return testCredentialAPI(serviceUrl, username, password, expectedStatus);
  }

  private Response testFilteredGroupCredentialAPI(String group, String username, String password, int expectedStatus) {
    final String serviceUrl = gatewayUrl + "/" + currentTopology + "/cab/api/v1/credentials/group/" + group;
    return testCredentialAPI(serviceUrl, username, password, expectedStatus);
  }

  private Response testCredentialAPI(String url, String username, String password, int expectedStatus) {
    String expectedContentType;
    switch(expectedStatus) {
      case HttpStatus.SC_OK:
        expectedContentType = "application/json";
        break;
      default:
        expectedContentType = "";
    }

    return given().auth().preemptive().basic(username, password)
           .then()
           .statusCode(expectedStatus)
           .contentType(expectedContentType)
           .when().get(url).andReturn();
  }

}

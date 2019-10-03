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
package org.apache.knox.gateway.service.idbroker;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.ResponseMetadata;
import com.amazonaws.regions.Region;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.model.AWSSecurityTokenServiceException;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLResult;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityResult;
import com.amazonaws.services.securitytoken.model.DecodeAuthorizationMessageRequest;
import com.amazonaws.services.securitytoken.model.DecodeAuthorizationMessageResult;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.amazonaws.services.securitytoken.model.GetFederationTokenRequest;
import com.amazonaws.services.securitytoken.model.GetFederationTokenResult;
import com.amazonaws.services.securitytoken.model.GetSessionTokenRequest;
import com.amazonaws.services.securitytoken.model.GetSessionTokenResult;
import com.amazonaws.services.securitytoken.model.RegionDisabledException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.service.idbroker.aws.KnoxAWSClient;
import org.junit.Test;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class KnoxAWSClientTest {
  @Test
  public void testAssumeRoleDisallowed() {
    final String testRole = "arn:test";
    final String responseErrorMessage =
                      "Cloud Access Broker (Undetermined) is not permitted to assume the resolved role " + testRole;

    AWSSecurityTokenServiceException exception = new AWSSecurityTokenServiceException("");
    exception.setStatusCode(403);
    exception.setErrorCode("Access Denied");
    exception.setServiceName("AWSSecurityTokenService");
    exception.setRequestId("Test");

    doTestAssumeRoleErrorResponse(createTestClient(exception), testRole, responseErrorMessage);
  }

  @Test
  public void testRegionDisabled() {
    final String exceptionMessage = "Region Disabled";
    final String testRole = "arn:test";
    final String responseErrorMessage =
        "Cloud Access Broker (Undetermined) could not assume the resolved role " + testRole + ": " + exceptionMessage +
        " (Service: AWSSecurityTokenService; Status Code: 0; Error Code: null; Request ID: null)";

    RegionDisabledException exception = new RegionDisabledException("Region Disabled");
    exception.setServiceName("AWSSecurityTokenService");

    doTestAssumeRoleErrorResponse(createTestClient(exception), testRole, responseErrorMessage);
  }

  private void doTestAssumeRoleErrorResponse(final KnoxAWSClient client,
                                             final String        testRole,
                                             final String        expectedErrorMessage) {
    // Invoke the IDBroker client
    try {
      client.getCredentialsForRole(testRole);
    } catch (Exception e) {
      Throwable cause = e.getCause();
      assertNotNull(cause);
      assertTrue(cause instanceof WebApplicationException);
      WebApplicationException wae = (WebApplicationException)cause;
      Response response = wae.getResponse();
      assertTrue(response.hasEntity());
      Object entity = response.getEntity();
      assertNotNull(entity);
      Map<String, String> parsedJSON = null;
      try {
        parsedJSON = parseJSON((String) entity);
      } catch (Exception ex) {
        fail("Expected valid JSON for the error response.");
      }
      assertEquals(expectedErrorMessage, parsedJSON.get("error"));
    }
  }

  private static KnoxAWSClient createTestClient(AmazonServiceException assumeRoleException) {
    KnoxAWSClient client = new KnoxAWSClient();

    // Setup the IDBroker client enough to allow the test to execute
    client.setConfigProvider(new TestConfigProvider());
    client.init(new Properties());

    // Plug in the test STS client
    try {
      Field stsClientField = client.getClass().getDeclaredField("stsClient");
      stsClientField.setAccessible(true);

      stsClientField.set(client, new TestAWSSecurityTokenService(assumeRoleException));
    } catch (Exception e) {
      fail(e.getMessage());
    }

    return client;
  }

  private static Map<String, String> parseJSON(final String json) throws Exception {
    ObjectMapper om = new ObjectMapper();
    return om.readValue(json, new TypeReference<Map<String, String>>(){});
  }

  private static class TestConfigProvider implements CloudClientConfigurationProvider {
    @Override
    public void init(GatewayConfig config, Properties context) {
    }

    @Override
    public String getName() {
      return null;
    }

    @Override
    public CloudClientConfiguration getConfig() {
      return new CloudClientConfiguration() {
        @Override
        public String getProperty(String name) {
          return null;
        }

        @Override
        public String getProperty(String name, String defaultValue) {
          return null;
        }

        @Override
        public String getUserRole(String user) {
          return null;
        }

        @Override
        public String getGroupRole(String group) {
          return null;
        }

        @Override
        public String getDefaultGroupForUser(String user) {
          return null;
        }

        @Override
        public Set<String> getAllRoles() {
          return null;
        }
      };
    }
  }

  /**
   * Test implementation that responds to assumeRole requests with an Exception.
   */
  private static class TestAWSSecurityTokenService implements AWSSecurityTokenService {

    private AmazonServiceException assumeRoleException;

    TestAWSSecurityTokenService(AmazonServiceException assumeRoleException) {
      this.assumeRoleException = assumeRoleException;
    }

    @Override
    public void setEndpoint(String s) {
    }

    @Override
    public void setRegion(Region region) {
    }

    @Override
    public AssumeRoleResult assumeRole(AssumeRoleRequest assumeRoleRequest) {
//      AWSSecurityTokenServiceException exception = new AWSSecurityTokenServiceException("");
//      exception.setStatusCode(403);
//      exception.setErrorCode("Access Denied");
//      exception.setServiceName("AWSSecurityTokenService");
//      exception.setRequestId("Test");
//      throw exception;
      throw assumeRoleException;
    }

    @Override
    public AssumeRoleWithSAMLResult assumeRoleWithSAML(AssumeRoleWithSAMLRequest assumeRoleWithSAMLRequest) {
      return null;
    }

    @Override
    public AssumeRoleWithWebIdentityResult assumeRoleWithWebIdentity(AssumeRoleWithWebIdentityRequest assumeRoleWithWebIdentityRequest) {
      return null;
    }

    @Override
    public DecodeAuthorizationMessageResult decodeAuthorizationMessage(DecodeAuthorizationMessageRequest decodeAuthorizationMessageRequest) {
      return null;
    }

    @Override
    public GetCallerIdentityResult getCallerIdentity(GetCallerIdentityRequest getCallerIdentityRequest) {
      return null;
    }

    @Override
    public GetFederationTokenResult getFederationToken(GetFederationTokenRequest getFederationTokenRequest) {
      return null;
    }

    @Override
    public GetSessionTokenResult getSessionToken(GetSessionTokenRequest getSessionTokenRequest) {
      return null;
    }

    @Override
    public GetSessionTokenResult getSessionToken() {
      return null;
    }

    @Override
    public void shutdown() {
    }

    @Override
    public ResponseMetadata getCachedResponseMetadata(AmazonWebServiceRequest amazonWebServiceRequest) {
      return null;
    }
  }
}

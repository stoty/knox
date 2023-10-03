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

import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithSamlRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithSamlResponse;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityResponse;
import software.amazon.awssdk.services.sts.model.DecodeAuthorizationMessageRequest;
import software.amazon.awssdk.services.sts.model.DecodeAuthorizationMessageResponse;
import software.amazon.awssdk.services.sts.model.GetAccessKeyInfoRequest;
import software.amazon.awssdk.services.sts.model.GetAccessKeyInfoResponse;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;
import software.amazon.awssdk.services.sts.model.GetFederationTokenRequest;
import software.amazon.awssdk.services.sts.model.GetFederationTokenResponse;
import software.amazon.awssdk.services.sts.model.GetSessionTokenRequest;
import software.amazon.awssdk.services.sts.model.GetSessionTokenResponse;
import software.amazon.awssdk.services.sts.model.RegionDisabledException;
import software.amazon.awssdk.services.sts.model.StsException;
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
import java.util.function.Consumer;

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

    AwsServiceException exception = StsException.builder()
        .statusCode(403).message("Access Denied")
        .awsErrorDetails(AwsErrorDetails.builder()
            .errorCode("Access Denied")
            .serviceName("AWSSecurityTokenService")
            .build())
        .requestId("Test")
        .build();

    final KnoxAWSClient testClient = createTestClient(exception);
    doTestAssumeRoleErrorResponse(
        testClient, testRole, responseErrorMessage);
  }

  @Test
  public void testRegionDisabled() {
    final String exceptionMessage = "Region Disabled";
    final String testRole = "arn:test";
    final String responseErrorMessage =
        "Cloud Access Broker (Undetermined) could not assume the resolved role " + testRole;

    final String responseReason = exceptionMessage +
            " (Service: AWSSecurityTokenService, Status Code: 0, Request ID: null)";

    RegionDisabledException exception = RegionDisabledException.builder()
        .message("Region Disabled")
        .awsErrorDetails(AwsErrorDetails.builder()
            .serviceName("AWSSecurityTokenService")
            .build())
        .build();

    doTestAssumeRoleErrorResponse(createTestClient(exception), testRole, responseErrorMessage, responseReason);
  }

  private void doTestAssumeRoleErrorResponse(final KnoxAWSClient client,
                                             final String        testRole,
                                             final String        expectedErrorMessage) {
    doTestAssumeRoleErrorResponse(client, testRole, expectedErrorMessage, null);
  }

  private void doTestAssumeRoleErrorResponse(final KnoxAWSClient client,
                                             final String        testRole,
                                             final String        expectedErrorMessage,
                                             final String        expectedReason) {
    // Invoke the IDBroker client
    try {
      client.getCredentialsForRole(testRole);
    } catch (Exception e) {
      Throwable cause = e.getCause();
      assertNotNull(cause);
      if (cause == null) {
        throw new AssertionError(e);
      }
      if (!(cause instanceof WebApplicationException)) {
        throw new AssertionError(cause);
      }
      WebApplicationException wae = (WebApplicationException)cause;
      Response response = wae.getResponse();
      assertTrue(response.hasEntity());
      Object entity = response.getEntity();
      assertNotNull(entity);
      Map<String, String> parsedJSON = null;
      try {
        parsedJSON = parseJSON((String) entity);
      } catch (Exception ex) {
        throw new AssertionError(ex);
      }
      assertEquals(expectedErrorMessage, parsedJSON.get("error"));
      if (expectedReason != null) {
        assertEquals(expectedReason, parsedJSON.get("reason"));
      }
    }
  }

  private static KnoxAWSClient createTestClient(AwsServiceException assumeRoleException) {
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
  private static class TestAWSSecurityTokenService implements StsClient {

    private AwsServiceException assumeRoleException;

    TestAWSSecurityTokenService(AwsServiceException assumeRoleException) {
      this.assumeRoleException = assumeRoleException;
    }

    @Override
    public String serviceName() {
      return SERVICE_NAME;
    }

    @Override
    public void close() {

    }

    @Override
    public AssumeRoleResponse assumeRole(AssumeRoleRequest assumeRoleRequest) {
//      StsException exception = new StsException("");
//      exception.setStatusCode(403);
//      exception.setErrorCode("Access Denied");
//      exception.setServiceName("AWSSecurityTokenService");
//      exception.setRequestId("Test");
//      throw exception;
      throw assumeRoleException;
    }

    @Override
    public AssumeRoleWithSamlResponse assumeRoleWithSAML(final AssumeRoleWithSamlRequest assumeRoleWithSamlRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public AssumeRoleWithSamlResponse assumeRoleWithSAML(final Consumer<AssumeRoleWithSamlRequest.Builder> assumeRoleWithSamlRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public AssumeRoleWithWebIdentityResponse assumeRoleWithWebIdentity(
        final AssumeRoleWithWebIdentityRequest assumeRoleWithWebIdentityRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public AssumeRoleWithWebIdentityResponse assumeRoleWithWebIdentity(final Consumer<AssumeRoleWithWebIdentityRequest.Builder> assumeRoleWithWebIdentityRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public DecodeAuthorizationMessageResponse decodeAuthorizationMessage(
        final DecodeAuthorizationMessageRequest decodeAuthorizationMessageRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public DecodeAuthorizationMessageResponse decodeAuthorizationMessage(final Consumer<DecodeAuthorizationMessageRequest.Builder> decodeAuthorizationMessageRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetAccessKeyInfoResponse getAccessKeyInfo(final GetAccessKeyInfoRequest getAccessKeyInfoRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetAccessKeyInfoResponse getAccessKeyInfo(final Consumer<GetAccessKeyInfoRequest.Builder> getAccessKeyInfoRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetCallerIdentityResponse getCallerIdentity()
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetCallerIdentityResponse getCallerIdentity(final GetCallerIdentityRequest getCallerIdentityRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetCallerIdentityResponse getCallerIdentity(final Consumer<GetCallerIdentityRequest.Builder> getCallerIdentityRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetFederationTokenResponse getFederationToken(final GetFederationTokenRequest getFederationTokenRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetFederationTokenResponse getFederationToken(final Consumer<GetFederationTokenRequest.Builder> getFederationTokenRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetSessionTokenResponse getSessionToken()
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetSessionTokenResponse getSessionToken(final GetSessionTokenRequest getSessionTokenRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }

    @Override
    public GetSessionTokenResponse getSessionToken(final Consumer<GetSessionTokenRequest.Builder> getSessionTokenRequest)
        throws AwsServiceException, SdkClientException {
      return null;
    }
  }
}

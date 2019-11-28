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
package org.apache.knox.gateway.service.idbroker.azure;

import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.service.idbroker.CloudClientConfigurationProvider;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerResource;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.impl.DefaultCryptoService;
import org.easymock.EasyMock;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.partialMockBuilder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class KnoxAzureClientTest {

  public static final String MSI_PASS_1 = "/subscriptions/cff0e60e-1029-4be1-ba99-063347c927ce/resourcegroups/ADLSGen2-smore/providers/Microsoft.ManagedIdentity/userAssignedIdentities/contributor_msi";
  public static final String MSI_PASS_2 = "/subscriptions/82a95411-be37-4c8b-832b-a68bf5cc2c88/resourceGroups/ashukla-dl8296/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test-contributor-msi";
  public static final String MSI_PASS_3 = "subscriptions/4596e1fd-3daf-4e3a-a3f8-6f463d419b0b/resourceGroups/ashukla-dl8296/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test-contributor-msi";
  public static final String MSI_FAIL = "/subscriptions/5c378889-2bd7-495d-965b-fff888a6654e/resourcegroups/ADLSGen2-smore/providers/userAssignedIdentities/contributor_msi";
  public static final String TOPOLOGY_NAME = "azure-cab";
  public static final String PASSWORD = "password";
  private static final String EXPIRED_TOKEN = "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkJCOENlRlZxeWFHckdOdWVoSklpTDRkZmp6dyIsImtpZCI6IkJCOENlRlZxeWFHckdOdWVoSklpTDRkZmp6dyJ9.eyJhdWQiOiJodHRwczovL3N0b3JhZ2UuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2Y2MzZlMWM0LTE4YTUtNGY4YS05ZTQxLWUyNDdiYWUxMzg3ZC8iLCJpYXQiOjE1NzQ2OTgzMzYsIm5iZiI6MTU3NDY5ODMzNiwiZXhwIjoxNTc0NzI3NDM2LCJhaW8iOiI0MlZnWUhoWlk1UzJXVkpsd2Z0TkQwd1hSazlaRFFBPSIsImFwcGlkIjoiZTdkZTBiMDEtY2ViOC00NDk2LTllNjItMDliN2E0MTA0MjNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZjYzNmUxYzQtMThhNS00ZjhhLTllNDEtZTI0N2JhZTEzODdkLyIsIm9pZCI6ImVmNDMzYThmLWQwNjMtNDUzMS04YmZiLTgxNTg0NWFjZjcwNyIsInN1YiI6ImVmNDMzYThmLWQwNjMtNDUzMS04YmZiLTgxNTg0NWFjZjcwNyIsInRpZCI6ImY2MzZlMWM0LTE4YTUtNGY4YS05ZTQxLWUyNDdiYWUxMzg3ZCIsInV0aSI6IjNLallNRDlJUFVxaXVhc283dG8wQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9lNTFjZWNlZi0xNTk4LTRiZmQtYTBlMS05ZDc4MTY3ZGZhY2IvcmVzb3VyY2Vncm91cHMvc2R4LW5mLXRlc3RpbmctcmcvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy9oYWRvb3BfdXNlciJ9.TTpo8VRnh_Ng2FGQoXNEvNLlAMMR2aNhUCv0DEZ2pYI5-6zYkaBJiZJfs42EN-Qyut5gxZDegIQUAFGyDfYoy3YFdiOWOfwzgOBFzdDguVI9p9p3z2_tbLm5XVW0Sd2a5noCYwzFrlqvTxUdDpNfpffIhf6fc7VEo-0uMFR6lE3eEMenFepEAo60GFFA32nWj6ZzRegPW4leMhJRkeey05bwQ88djIot4uIAgTntT2aNxksTUv7FDkdsI5MSqUiEBZ2nZl6NRyKC5Ta7dOvYV3Jmso_DD-brOu4rhsZfAlwS9t1mbSHr9Vw5A0AidqFXlZeQpkuA7bOIMpmb29ircg\",\"client_id\":\"e7de0b01-ceb8-4496-9e62-09b7a410423e\",\"expires_in\":\"28800\",\"expires_on\":\"1574727436\",\"ext_expires_in\":\"28800\",\"not_before\":\"1574698336\",\"resource\":\"https://storage.azure.com/\",\"token_type\":\"Bearer\"}";
  private static final String CURRENT_TOKEN =
      "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkJCOENlRlZxeWFHckdOdWVoSklpTDRkZmp6dyIsImtpZCI6IkJCOENlRlZxeWFHckdOdWVoSklpTDRkZmp6dyJ9.eyJhdWQiOiJodHRwczovL3N0b3JhZ2UuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2Y2MzZlMWM0LTE4YTUtNGY4YS05ZTQxLWUyNDdiYWUxMzg3ZC8iLCJpYXQiOjE1NzQ2OTgzMzYsIm5iZiI6MTU3NDY5ODMzNiwiZXhwIjoxNTc0NzI3NDM2LCJhaW8iOiI0MlZnWUhoWlk1UzJXVkpsd2Z0TkQwd1hSazlaRFFBPSIsImFwcGlkIjoiZTdkZTBiMDEtY2ViOC00NDk2LTllNjItMDliN2E0MTA0MjNlIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZjYzNmUxYzQtMThhNS00ZjhhLTllNDEtZTI0N2JhZTEzODdkLyIsIm9pZCI6ImVmNDMzYThmLWQwNjMtNDUzMS04YmZiLTgxNTg0NWFjZjcwNyIsInN1YiI6ImVmNDMzYThmLWQwNjMtNDUzMS04YmZiLTgxNTg0NWFjZjcwNyIsInRpZCI6ImY2MzZlMWM0LTE4YTUtNGY4YS05ZTQxLWUyNDdiYWUxMzg3ZCIsInV0aSI6IjNLallNRDlJUFVxaXVhc283dG8wQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9lNTFjZWNlZi0xNTk4LTRiZmQtYTBlMS05ZDc4MTY3ZGZhY2IvcmVzb3VyY2Vncm91cHMvc2R4LW5mLXRlc3RpbmctcmcvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy9oYWRvb3BfdXNlciJ9.TTpo8VRnh_Ng2FGQoXNEvNLlAMMR2aNhUCv0DEZ2pYI5-6zYkaBJiZJfs42EN-Qyut5gxZDegIQUAFGyDfYoy3YFdiOWOfwzgOBFzdDguVI9p9p3z2_tbLm5XVW0Sd2a5noCYwzFrlqvTxUdDpNfpffIhf6fc7VEo-0uMFR6lE3eEMenFepEAo60GFFA32nWj6ZzRegPW4leMhJRkeey05bwQ88djIot4uIAgTntT2aNxksTUv7FDkdsI5MSqUiEBZ2nZl6NRyKC5Ta7dOvYV3Jmso_DD-brOu4rhsZfAlwS9t1mbSHr9Vw5A0AidqFXlZeQpkuA7bOIMpmb29ircg\",\"client_id\":\"e7de0b01-ceb8-4496-9e62-09b7a410423e\",\"expires_in\":\"28800\",\"expires_on\":\""
          + (System.currentTimeMillis() / 1000) + 30000
          + "\",\"ext_expires_in\":\"28800\",\"not_before\":\"" + (
          System.currentTimeMillis() / 1000) + 30000
          + "\",\"resource\":\"https://storage.azure.com/\",\"token_type\":\"Bearer\"}";
  private static final String ALIAS_PASSWORD = "pwdfortest";
  private static final String AZURE_SKEW_OFFSET_SECONDS = "5";
  public static Pattern MSI_PATTERN = Pattern
      .compile(KnoxAzureClient.MSI_PATH_REGEX_NAMED);
  private static KnoxAzureClient azureClient;
  private static CloudClientConfiguration config = (new TestConfigProvider())
      .getConfig();

  @BeforeClass
  public static void init() throws AliasServiceException {
    final AliasService aliasService = EasyMock
        .createNiceMock(AliasService.class);
    EasyMock.expect(aliasService.getPasswordFromAliasForCluster(TOPOLOGY_NAME,
        IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS))
        .andReturn(ALIAS_PASSWORD.toCharArray()).anyTimes();
    EasyMock.replay(aliasService);

    final DefaultCryptoService cryptoService = new DefaultCryptoService();
    cryptoService.setAliasService(aliasService);

    azureClient = partialMockBuilder(KnoxAzureClient.class)
        .addMockedMethods("getCachedAccessToken", "getConfigProvider",
            "generateAccessToken").createMock();
    /* always return expired token from cache */
    EasyMock.expect(azureClient.getCachedAccessToken(anyString()))
        .andReturn(EXPIRED_TOKEN).anyTimes();
    EasyMock.expect(azureClient.getConfigProvider())
        .andReturn(new TestConfigProvider()).anyTimes();
    /* mock expired token */
    EasyMock
        .expect(azureClient.generateAccessToken(anyObject(), eq(MSI_PASS_1)))
        .andReturn(EXPIRED_TOKEN).anyTimes();
    /* mock un-expired token */
    EasyMock
        .expect(azureClient.generateAccessToken(anyObject(), eq(MSI_PASS_2)))
        .andReturn(CURRENT_TOKEN).anyTimes();
    EasyMock.replay(azureClient);

    /* set up test properties */
    final Properties props = new Properties();
    props.setProperty("topology.name", TOPOLOGY_NAME);
    props.setProperty("credential.cache.ttl", "10");

    azureClient.setAliasService(aliasService);
    azureClient.setCryptoService(cryptoService);
    azureClient.init(props);
  }

  /**
   * test to check MSI name pattern used to validate MSI names.
   */
  @Test
  public void testMSITokenNamePattern() {
    /* test for resourcegroup */
    Matcher matcher = KnoxAzureClient.MSI_PATH_PATTERN.matcher(MSI_PASS_1);
    if (matcher.matches()) {
      assertEquals("cff0e60e-1029-4be1-ba99-063347c927ce",
          matcher.group("subscription"));
      assertEquals("ADLSGen2-smore", matcher.group("resourceGroup"));
      assertEquals("contributor_msi", matcher.group("vmName"));
    } else {
      fail("No Match found");
    }

    /* test for resourceGroup */
    matcher = KnoxAzureClient.MSI_PATH_PATTERN.matcher(MSI_PASS_2);
    if (matcher.matches()) {
      assertEquals("82a95411-be37-4c8b-832b-a68bf5cc2c88",
          matcher.group("subscription"));
      assertEquals("ashukla-dl8296", matcher.group("resourceGroup"));
      assertEquals("test-contributor-msi", matcher.group("vmName"));
    } else {
      fail("No Match found");
    }

    /* test for subscription without forward / */
    matcher = KnoxAzureClient.MSI_PATH_PATTERN.matcher(MSI_PASS_3);
    if (matcher.matches()) {
      assertEquals("4596e1fd-3daf-4e3a-a3f8-6f463d419b0b",
          matcher.group("subscription"));
      assertEquals("ashukla-dl8296", matcher.group("resourceGroup"));
      assertEquals("test-contributor-msi", matcher.group("vmName"));
    } else {
      fail("No Match found");
    }

    /* test for invalid MSI name  */
    matcher = KnoxAzureClient.MSI_PATH_PATTERN.matcher(MSI_FAIL);
    if (matcher.matches()) {
      fail("Matched invalid name");
    }

  }

  /**
   * Test case where IDB Cache returns an expired token. Instead of returning
   * the expired token attempt to get a new token from Azure and check if it is
   * valid, if it is expired keep trying using the configured property
   * values<br/> ** azure.retry.delay<br/> ** azure.token.skew.offset<br/>
   *
   * @throws AliasServiceException
   */
  @Test(timeout = 10000)
  public void testExpiredTokenFromAzure() throws AliasServiceException {
    long t1 = System.currentTimeMillis();
    azureClient.getCredentialsForRole(MSI_PASS_1);
    long t2 = System.currentTimeMillis();
    assertEquals(azureClient.generateAccessToken(config, MSI_PASS_1),
        EXPIRED_TOKEN);
    /* in case of expired token returned from Azure backend make sure the calls are blocked for the amount of skew offset configured */
    assertTrue(
        "Calls should be blocked for skew offset time before returning expired token",
        ((t2 - t1) / 1000 >= Long.parseLong(AZURE_SKEW_OFFSET_SECONDS)));
  }

  /**
   * test case where 1. Cache returns expired token 2. Go to Azure back end
   * (mocked) and get a valid token Make sure we don't block and return
   * immediately.
   *
   * @throws AliasServiceException
   */
  @Test(timeout = 3000)
  public void testCacheExpiredToken() throws AliasServiceException {
    long t1 = System.currentTimeMillis();
    azureClient.getCredentialsForRole(MSI_PASS_2);
    long t2 = System.currentTimeMillis();
    assertEquals(azureClient.generateAccessToken(config, MSI_PASS_2),
        CURRENT_TOKEN);
    /* make sure that the token returns immediately */
    assertTrue(
        "Calls should be blocked for skew offset time before returning expired token",
        ((t2 - t1) / 1000 <= 1));
  }

  private static class TestConfigProvider
      implements CloudClientConfigurationProvider {
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
          if ("topology.name".equalsIgnoreCase(name)) {
            return TOPOLOGY_NAME;
          }
          return null;
        }

        @Override
        public String getProperty(String name, String defaultValue) {

          if ("azure.retry.delay".equalsIgnoreCase(name)) {
            return "1";
          }

          if ("azure.token.skew.offset".equalsIgnoreCase(name)) {
            return AZURE_SKEW_OFFSET_SECONDS;
          }

          return defaultValue;
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

}

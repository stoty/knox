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
package org.apache.knox.gateway.service.idbroker.aws;

import com.google.common.annotations.VisibleForTesting;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.AwsRegionProviderChain;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.AssumedRoleUser;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;
import software.amazon.awssdk.services.sts.model.MalformedPolicyDocumentException;
import software.amazon.awssdk.services.sts.model.PackedPolicyTooLargeException;
import software.amazon.awssdk.services.sts.model.RegionDisabledException;
import software.amazon.awssdk.services.sts.model.StsException;

import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.service.idbroker.AbstractKnoxCloudCredentialsClient;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerConfigException;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerResource;
import org.apache.knox.gateway.service.idbroker.ResponseUtils;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.EncryptionResult;
import org.apache.knox.gateway.util.JsonUtils;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

public class KnoxAWSClient extends AbstractKnoxCloudCredentialsClient {
  private static final String NAME = "AWS";
  private static final String CAB_SESSION_NAME_PREFIX = "CAB-SESSION-";
  private static final String AWS_REGION_PROPERTY = "aws.region.name";

  private static final AWSClientMessages LOG = MessagesFactory.get(AWSClientMessages.class);

  private static final AwsRegionProviderChain DEFAULT_AWS_REGION_PROVIDER_CHAIN = new DefaultAwsRegionProviderChain();

  /**
   * This field is patched in {@code KnoxAWSClientTest}: do not rename.
   */
  private StsClient stsClient;
  private String stsClientIdentity;

  protected String regionName;

  protected int tokenLifetime = 3600; // AWS default value

  private StsClient getSTSClient() {
    if (stsClient == null) {
      final StsClientBuilder awsSTSClientBuilder = StsClient.builder()
          .credentialsProvider(new KnoxAWSCredentialsProviderList());

      String region = getRegion();
      awsSTSClientBuilder.endpointOverride(getSTSEndpoint(region))
          .region(Region.of(region));
      stsClient = awsSTSClientBuilder.build();
    }
    return stsClient;
  }

  /**
   * Given an AWS region, create the STS endpoint URI.
   *
   * @param region AWS Region
   * @return an endpoint uri
   */
  @VisibleForTesting
  public static URI getSTSEndpoint(String region) {
    try {
      return new URI(String.format(Locale.ROOT, "https://sts.%s.amazonaws.com", region));
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public void init(Properties context) {
    super.init(context);
    regionName = context.getProperty(AWS_REGION_PROPERTY);

    String ttlValue = context.getProperty("token.lifetime");
    if (ttlValue != null && !ttlValue.isEmpty()) {
      try {
        tokenLifetime = Integer.parseInt(ttlValue);
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("token.lifetime configuration property value must be an integer.");
      }
    }
  }

  private String getClientIdentity() {
    if (stsClientIdentity == null) {
      GetCallerIdentityResponse callerIdentityResult = stsClient.getCallerIdentity(
          GetCallerIdentityRequest.builder().build());
      if (callerIdentityResult != null) {
        stsClientIdentity = callerIdentityResult.arn();
      }
    }
    return (stsClientIdentity != null ? stsClientIdentity : "Undetermined");
  }

  @Override
  public Object getCredentials() {
    return getCredentialsForRole(getRole());
  }

  @Override
  public Object getCredentialsForRole(String role) {
    return getAssumeRoleResultCached(getConfigProvider().getConfig(), role);
  }

  /**
   * Return cached credentials
   * @param config
   * @param role
   * @return result in jSON
   */
  private String getAssumeRoleResultCached(final CloudClientConfiguration config, final String role) {

    String result;
    try {
      // Get the credentials from cache, if the credentials are not in cache use the function to load the cache.
      // Credentials are encrypted and cached
      final EncryptionResult encrypted = credentialCache.get(role, () -> {
        /* encrypt credentials and cache them as JSON */
        final String json = convertToJSON(getAssumeRoleResult(config, role));
        return cryptoService.encryptForCluster(topologyName,
            IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS, json.getBytes(StandardCharsets.UTF_8));
      });

      /* decrypt the credentials from cache */
      byte[] serialized = cryptoService.decryptForCluster(topologyName, IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS, encrypted.cipher, encrypted.iv, encrypted.salt);
      result = new String(serialized, StandardCharsets.UTF_8);

    } catch (final ExecutionException e) {
      LOG.cacheException(role, e.toString());
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
    return result;
  }

  @SuppressWarnings("unused")
  private AssumeRoleResponse getAssumeRoleResult(CloudClientConfiguration config, String role) {
    AssumeRoleResponse result;

    AssumeRoleRequest request = AssumeRoleRequest.builder()
        .roleSessionName(generateRoleSessionName())
        .roleArn(role)
        .durationSeconds(tokenLifetime)
        .build();

    try {
      result = getSTSClient().assumeRole(request);
    } catch (MalformedPolicyDocumentException | PackedPolicyTooLargeException | RegionDisabledException e) {
      String responseEntity =
              ResponseUtils.createErrorResponseJSON("Cloud Access Broker (%s) could not assume the resolved role %s",
                                                    e.getMessage(),
                                                    getClientIdentity(),
                                                    role);
      Response response = Response.status(e.statusCode())
                                  .entity(responseEntity)
                                  .build();
      throw new WebApplicationException(response);
    } catch (StsException e) {
      String clientId = getClientIdentity();
      LOG.assumeRoleDisallowed(clientId, role, e.getMessage());
      String responseEntity =
        ResponseUtils.createErrorResponseJSON("Cloud Access Broker (%s) is not permitted to assume the resolved role %s",
                                              e.getMessage(),
                                              clientId,
                                              role);
      Response response = Response.status(Response.Status.FORBIDDEN)
                                  .entity(responseEntity)
                                  .build();
      throw new WebApplicationException(response);
    } catch (RuntimeException e) {
      String errorMessage;
      Throwable t = e.getCause();
      if (t != null && IdentityBrokerConfigException.class.isAssignableFrom(t.getClass())) {
        errorMessage = t.getMessage();
        LOG.cabConfigurationError(t.getMessage());
      } else {
        errorMessage = e.getMessage();
        LOG.logException(e);
      }

      Response response = Response.serverError()
                                  .entity(ResponseUtils.createErrorResponseJSON(errorMessage))
                                  .build();
      throw new WebApplicationException(response);
    }

    return result;
  }

  private String generateRoleSessionName() {
    return CAB_SESSION_NAME_PREFIX + System.currentTimeMillis();
  }

  private String getRegion() {
    // Use the explicitly configured region if specified
    if (regionName != null) {
      return regionName;
    }

    // If there is no explicit configured region, try to determine the current region
    try {
      // Use the same logic as the default AwsClientBuilder for region lookup
      return DEFAULT_AWS_REGION_PROVIDER_CHAIN.getRegion().id();
    } catch (SdkClientException ignore) {
      // we don't want to throw an exception, but the current AWS SDK
      // default aws region provider chain throws an exception
    }

    // Fall back to a us-east-1 default region if no other region determined or configured.
    return Region.US_EAST_1.id();
  }

  private class KnoxAWSCredentialsProviderList implements AwsCredentialsProvider {
    AwsCredentialsProvider aliasCredsProvider = new AliasServiceAWSCredentialsProvider();
    AwsCredentialsProvider ipCredsProvider = InstanceProfileCredentialsProvider.builder()
        .build();
    AwsCredentialsProvider credsProvider;

    @Override
    public AwsCredentials resolveCredentials() {
      credsProvider = aliasCredsProvider;
      AwsCredentials creds = credsProvider.resolveCredentials();

      if (creds == null) {
        credsProvider = ipCredsProvider;
        try {
          creds = credsProvider.resolveCredentials();
        } catch (Exception e) {
          LOG.cabConfigurationError(e.getMessage());
        }
      }

      if (creds == null) {
        throw new RuntimeException(new IdentityBrokerConfigException("Missing required credential provisioning for Cloud Access Broker. "
            + "It is expected that keys and secrets be provisioned as aliases or that Cloud Access Broker be running on a node with an Instance Profile attached."));
      }

      return creds;
    }

  }

  private class AliasServiceAWSCredentialsProvider implements AwsCredentialsProvider {

    static final String KEY_ALIAS_NAME    = "aws.credentials.key";
    static final String SECRET_ALIAS_NAME = "aws.credentials.secret";

    @Override
    public AwsCredentials resolveCredentials() {
      String key = getClusterAliasValue(KEY_ALIAS_NAME);
      String secret = getClusterAliasValue(SECRET_ALIAS_NAME);
      if (key == null || secret == null) {
        return null;
      }
      return new AwsCredentials() {
        @Override
        public String accessKeyId() {
          return key;
        }

        @Override
        public String secretAccessKey() {
          return secret;
        }

      };
    }

    private String getClusterAliasValue(String alias) {
      String aliasValue = null;
      try {
        char[] value = aliasService.getPasswordFromAliasForCluster(topologyName, alias);
        if (value == null) {
          LOG.aliasConfigurationError(alias);
        } else {
          aliasValue = new String(value);
        }
      } catch (AliasServiceException e) {
        LOG.logException(e);
      }
      return aliasValue;
    }

  }

  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Convert the AssumeRoleResponse to a JSON string.
   * @param result response from STS.
   * @return JSON string.
   */
  @VisibleForTesting
  public static String convertToJSON(AssumeRoleResponse result) {
    Map<String, Object> model = new HashMap<>();

//  {
//    Credentials: {
//      AccessKeyId: XXX,
//      SecretAccessKey: XXX,
//      SessionToken: XXX,
//      Expiration: Wed Oct 17 10:32:41 EDT 2018
//    },
//    AssumedRoleUser: {
//      AssumedRoleId: XXX:CAB-SESSION-1539783161329,
//      Arn: arn:aws:sts::XXX:assumed-role/s3Read/CAB-SESSION-1539783161329
//    },
//  }

    Map<String, Object> credsModel = new HashMap<>();
    Credentials creds = result.credentials();

    credsModel.put("AccessKeyId", creds.accessKeyId());
    credsModel.put("SecretAccessKey", creds.secretAccessKey());
    credsModel.put("SessionToken", creds.sessionToken());
    credsModel.put("Expiration", creds.expiration().toEpochMilli());
    model.put("Credentials", credsModel);

    Map<String, Object> assumedRoleUserModel = new HashMap<>();
    AssumedRoleUser aru = result.assumedRoleUser();
    assumedRoleUserModel.put("AssumedRole", aru.assumedRoleId());
    assumedRoleUserModel.put("Arn", aru.arn());
    model.put("AssumedRoleUser", assumedRoleUserModel);

    return JsonUtils.renderAsJsonString(model);
  }
}

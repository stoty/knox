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

import com.amazonaws.regions.Region;
import com.amazonaws.services.securitytoken.model.AWSSecurityTokenServiceException;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.AssumedRoleUser;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.amazonaws.services.securitytoken.model.MalformedPolicyDocumentException;
import com.amazonaws.services.securitytoken.model.PackedPolicyTooLargeException;
import com.amazonaws.services.securitytoken.model.RegionDisabledException;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.service.idbroker.AbstractKnoxCloudCredentialsClient;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerConfigException;
import org.apache.knox.gateway.service.idbroker.IdentityBrokerResource;
import org.apache.knox.gateway.services.security.AliasServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import org.apache.knox.gateway.services.security.EncryptionResult;
import org.apache.knox.gateway.util.JsonUtils;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

public class KnoxAWSClient extends AbstractKnoxCloudCredentialsClient {

  private static final String NAME = "AWS";

  private static final String CAB_SESSION_NAME_PREFIX = "CAB-SESSION-";

  private static final String AWS_REGION_PROPERTY = "aws.region.name";

  private static AWSClientMessages LOG = MessagesFactory.get(AWSClientMessages.class);

  private AWSSecurityTokenService stsClient = null;

  private String stsClientIdentity;

  protected String regionName;

  protected int tokenLifetime = 3600; // AWS default value

  private AWSSecurityTokenService getSTSClient() {
    if (stsClient == null) {
      AWSCredentialsProvider credsProvider = new KnoxAWSCredentialsProviderList();

      stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                                                      .withCredentials(credsProvider)
                                                      .withRegion(getRegion())
                                                      .build();
    }
    return stsClient;
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
      GetCallerIdentityResult callerIdentityResult = stsClient.getCallerIdentity(new GetCallerIdentityRequest());
      if (callerIdentityResult != null) {
        stsClientIdentity = callerIdentityResult.getArn();
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
    return convertToJSON(getAssumeRoleResultCached(getConfigProvider().getConfig(), role));
  }

  /**
   * Return cached credentials
   * @param config
   * @param role
   * @return
   */
  private AssumeRoleResult getAssumeRoleResultCached(final CloudClientConfiguration config, final String role) {

    AssumeRoleResult result;
    try {
      // Get the credentials from cache, if the credentials are not in cache use the function to load the cache.
      // Credentials are encrypted and cached
      final EncryptionResult encrypted = credentialCache.get(role, () -> {
        /* encrypt credentials and cache them */
        return cryptoService.encryptForCluster(topologyName,
            IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS, SerializationUtils.serialize(getAssumeRoleResult(config, role)));
      });

      /* decrypt the credentials from cache */
      byte[] serialized = cryptoService.decryptForCluster(topologyName, IdentityBrokerResource.CREDENTIAL_CACHE_ALIAS, encrypted.cipher, encrypted.iv, encrypted.salt);
      result = SerializationUtils.deserialize(serialized);

    } catch (final ExecutionException e) {
      LOG.cacheException(role, e.toString());
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
    return result;
  }

  private AssumeRoleResult getAssumeRoleResult(CloudClientConfiguration config, String role) {
    AssumeRoleResult result;

    AssumeRoleRequest request = new AssumeRoleRequest().withRoleSessionName(generateRoleSessionName())
                                                       .withRoleArn(role)
                                                       .withDurationSeconds(tokenLifetime);

    try {
      result = getSTSClient().assumeRole(request);
    } catch (MalformedPolicyDocumentException | PackedPolicyTooLargeException | RegionDisabledException e) {
      throw new WebApplicationException(e.getMessage(), e.getStatusCode());
    } catch (AWSSecurityTokenServiceException e) {
      LOG.assumeRoleDisallowed(getClientIdentity(), role, e.getMessage());
      throw new WebApplicationException(Response.Status.FORBIDDEN);
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
                                  .entity(String.format(Locale.getDefault(), "{ \"error\": \"%s\" }", errorMessage))
                                  .build();
      throw new WebApplicationException(response);
    }

    return result;
  }

  private String generateRoleSessionName() {
    return CAB_SESSION_NAME_PREFIX + System.currentTimeMillis();
  }

  private Regions getRegion() {
    Regions region = null;

    if (regionName != null) {
      region = Regions.fromName(regionName);
    }

    // If the configured region is not valid, try the current region
    if (region == null) {
      Region current = Regions.getCurrentRegion();
      if (current != null) {
        region = Regions.fromName(current.getName());
      }
    }

    // Finally, fall back to the default
    if (region == null) {
      region = Regions.US_EAST_1;
    }

    return region;
  }

  private class KnoxAWSCredentialsProviderList implements AWSCredentialsProvider {

    AWSCredentialsProvider aliasCredsProvider = new AliasServiceAWSCredentialsProvider();
    AWSCredentialsProvider ipCredsProvider = new InstanceProfileCredentialsProvider(true);
    AWSCredentialsProvider credsProvider = null;

    @Override
    public AWSCredentials getCredentials() {
      credsProvider = aliasCredsProvider;
      AWSCredentials creds = credsProvider.getCredentials();

      if (creds == null) {
        credsProvider = ipCredsProvider;
        try {
          creds = credsProvider.getCredentials();
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

    @Override
    public void refresh() {
      if (credsProvider != null) {
        credsProvider.refresh();
      }
    }
  }

  private class AliasServiceAWSCredentialsProvider implements AWSCredentialsProvider {

    static final String KEY_ALIAS_NAME    = "aws.credentials.key";
    static final String SECRET_ALIAS_NAME = "aws.credentials.secret";

    @Override
    public AWSCredentials getCredentials() {
      String key = getClusterAliasValue(KEY_ALIAS_NAME);
      String secret = getClusterAliasValue(SECRET_ALIAS_NAME);
      if (key == null || secret == null) {
        return null;
      }
      return new AWSCredentials() {
        @Override
        public String getAWSAccessKeyId() {
          return key;
        }

        @Override
        public String getAWSSecretKey() {
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

    @Override
    public void refresh() {
    }
  }

  @Override
  public String getName() {
    return NAME;
  }

  private String convertToJSON(AssumeRoleResult result) {
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
    Credentials creds = result.getCredentials();

    credsModel.put("AccessKeyId", creds.getAccessKeyId());
    credsModel.put("SecretAccessKey", creds.getSecretAccessKey());
    credsModel.put("SessionToken", creds.getSessionToken());
    credsModel.put("Expiration", creds.getExpiration());
    model.put("Credentials", credsModel);

    Map<String, Object> assumedRoleUserModel = new HashMap<>();
    AssumedRoleUser aru = result.getAssumedRoleUser();
    assumedRoleUserModel.put("AssumedRole", aru.getAssumedRoleId());
    assumedRoleUserModel.put("Arn", aru.getArn());
    model.put("AssumedRoleUser", assumedRoleUserModel);

    return JsonUtils.renderAsJsonString(model);
  }

}

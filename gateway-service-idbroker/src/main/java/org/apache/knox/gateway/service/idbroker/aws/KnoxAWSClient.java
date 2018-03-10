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
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.AssumedRoleUser;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.MalformedPolicyDocumentException;
import com.amazonaws.services.securitytoken.model.PackedPolicyTooLargeException;
import com.amazonaws.services.securitytoken.model.RegionDisabledException;
import org.apache.knox.gateway.service.idbroker.AbstractKnoxCloudCredentialsClient;
import org.apache.knox.gateway.service.idbroker.CloudClientConfiguration;
import org.apache.knox.gateway.services.security.AliasServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import org.apache.knox.gateway.util.JsonUtils;

import javax.ws.rs.WebApplicationException;
import java.util.HashMap;
import java.util.Map;


public class KnoxAWSClient extends AbstractKnoxCloudCredentialsClient {

  private static final String CAB_SESSION_NAME_PREFIX = "CAB-SESSION-";

  private static final String AWS_REGION_PROPERTY = "aws.region.name";


  @Override
  public Object getCredentials() {
    return getCredentialsForRole(getRole());
  }

  @Override
  public Object getCredentialsForRole(String role) {
    return convertToJSON(getAssumeRoleResult(getConfigProvider().getConfig(), role));
  }

  private AssumeRoleResult getAssumeRoleResult(CloudClientConfiguration config, String role) {
    AssumeRoleResult result;

    // TODO: Could this client be re-used across credential requests, rather than creating a new one every time?
    AWSSecurityTokenService sts_client =
        AWSSecurityTokenServiceClientBuilder.standard()
                                            .withCredentials(new AliasServiceAWSCredentialsProvider())
                                            .withRegion(getRegion())
                                            .build();

    String roleToAssume = role != null ? role : (String) config.getProperty("role");
    AssumeRoleRequest request = new AssumeRoleRequest().withRoleSessionName(generateRoleSessionName())
                                                       .withRoleArn(roleToAssume);

    try {
      result = sts_client.assumeRole(request);
      System.out.println(result.getCredentials());
    } catch (MalformedPolicyDocumentException | PackedPolicyTooLargeException | RegionDisabledException e) {
      throw new WebApplicationException(e.getMessage(), e.getStatusCode());
    }

    return result;
  }

  private String generateRoleSessionName() {
    return CAB_SESSION_NAME_PREFIX + System.currentTimeMillis();
  }

  private Regions getRegion() {
    Regions region = null;

    String regionName = (String) getConfigProvider().getConfig().getProperty(AWS_REGION_PROPERTY);
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

  private class AliasServiceAWSCredentialsProvider implements AWSCredentialsProvider {
    @Override
    public AWSCredentials getCredentials() {
      return new AWSCredentials() {
        @Override
        public String getAWSAccessKeyId() {
          try {
            return new String(aliasService.getPasswordFromAliasForCluster(topologyName, "aws.credentials.key"));
          } catch (AliasServiceException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
          }
          return null;
        }

        @Override
        public String getAWSSecretKey() {
          try {
            return new String(aliasService.getPasswordFromAliasForCluster(topologyName, "aws.credentials.secret"));
          } catch (AliasServiceException e) {
            // TODO Auto-generated catch block
              e.printStackTrace();
          }
          return null;
        }
      };
    }

    @Override
    public void refresh() {
    }
  }

  @Override
  public String getName() {
    return "AWS";
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

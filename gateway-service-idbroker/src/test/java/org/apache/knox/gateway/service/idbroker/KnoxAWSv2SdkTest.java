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

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.Instant;

import org.junit.Test;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.AssumedRoleUser;
import software.amazon.awssdk.services.sts.model.Credentials;

import static org.apache.knox.gateway.service.idbroker.aws.KnoxAWSClient.convertToJSON;
import static org.apache.knox.gateway.service.idbroker.aws.KnoxAWSClient.getSTSEndpoint;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Extra tests related to AWS V2 integration, especially the where there
 * were tangible failures.
 * Partially based on {@code AuthResponseAWSMessageTest}.
 */
public class KnoxAWSv2SdkTest {

  static final String ASSUMED_ROLE = "ABCDEFGHIJKLABCDEFGHIJKL:ABC-DEFGH-15000000011";

  static final String ARN
      = "arn:aws:sts::000000000000:assumed-role/stevel-s3guard/ABC-DEFGH-15000000011";

  static final String ACCESS_KEY = "ABCDEFGHIJKL";

  static final String SECRET_ACCESS_KEY = "2vzXdfOba+AbCd+abcd134ABCDO/acd";

  static final String SESSION_TOKEN
      = "FQoGZXIvYXdzANL//////////wABCDEFGHIJKL/ABCDEFGHIJKL/ABCDEFGHIJKL";

  /**
   * Test that the region mapping returns hostnames which
   * resolve.
   */
  @Test
  public void testRegionToEndpointMapping() throws Throwable {
    // validate region mapping
    assertRegionMapping(Region.US_EAST_1.id(), "https://sts.us-east-1.amazonaws.com");
    assertRegionMapping(Region.US_EAST_2.id(), "https://sts.us-east-2.amazonaws.com");
    assertRegionMapping(Region.EU_WEST_1.id(), "https://sts.eu-west-1.amazonaws.com");
    assertRegionMapping(Region.US_GOV_WEST_1.id(), "https://sts.us-gov-west-1.amazonaws.com");
  }

  /**
   * Assert a region maps to a specific endpoint.
   *
   * @param region region
   * @param endpoint expected endpoint
   *
   * @throws URISyntaxException if the endpoint is not a valid URI
   * @throws UnknownHostException generated hostname is not a real host
   */
  private static void assertRegionMapping(final String region, final String endpoint)
      throws URISyntaxException, UnknownHostException {
    final URI uri = getSTSEndpoint(region);
    assertEquals("Wrong endpoint for region " + region,
        endpoint, new URI(endpoint).toString());

    InetAddress.getByName(uri.getHost());
  }

  /**
   * AWS V2 completely broke serialization.
   */
  @Test
  public void testCredentialSerialization() throws Throwable {
    final long now = System.currentTimeMillis();
    final Instant expiration = Instant.ofEpochMilli(now);

    final Credentials credentials = Credentials.builder()
        .accessKeyId(ACCESS_KEY)
        .secretAccessKey(SECRET_ACCESS_KEY)
        .sessionToken(SESSION_TOKEN)
        .expiration(expiration)
        .build();
    final AssumedRoleUser aru = AssumedRoleUser.builder()
        .arn(ARN)
        .assumedRoleId(ASSUMED_ROLE)
        .build();
    final AssumeRoleResponse response = AssumeRoleResponse.builder()
        .credentials(credentials)
        .assumedRoleUser(aru)
        .build();
    final String json = convertToJSON(response);
    assertNotNull("json not generated", json);

    final MarshalledAuthResponseMessage message = MarshalledAuthResponseMessage.serializer()
        .fromJson(json);

    assertEquals(ASSUMED_ROLE, message.AssumedRoleUser.AssumedRole);
    assertEquals(ARN, message.AssumedRoleUser.Arn);
    assertEquals(ACCESS_KEY, message.Credentials.AccessKeyId);
    assertEquals(SECRET_ACCESS_KEY, message.Credentials.SecretAccessKey);
    assertEquals(SESSION_TOKEN, message.Credentials.SessionToken);
    assertEquals(now, message.Credentials.Expiration);
  }
}


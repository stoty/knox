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

package org.apache.knox.gateway.cloud.idbroker.s3a;


import static org.junit.Assert.assertEquals;
import static org.testng.Assert.assertNull;

import org.apache.hadoop.util.JsonSerialization;
import org.junit.Test;

import java.io.IOException;

/**
 * Test Parsing of AuthResponseAWSMessage responses.
 */
public class AuthResponseAWSMessageTest {

  static final String ASSUMED_ROLE = "ABCDEFGHIJKLABCDEFGHIJKL:ABC-DEFGH-15000000011";

  static final String ARN = "arn:aws:sts::000000000000:assumed-role/stevel-s3guard/ABC-DEFGH-15000000011";

  static final String ACCESS_KEY = "ABCDEFGHIJKL";

  static final String SECRET_ACCESS_KEY = "2vzXdfOba+AbCd+abcd134ABCDO/acd";

  static final String SESSION_TOKEN = "FQoGZXIvYXdzANL//////////wABCDEFGHIJKL/ABCDEFGHIJKL/ABCDEFGHIJKL";

  static final String EXPIRATION = "1540228070000";
  /**
   * A valid response.
   * All strings have been edited other than the expiration date; the session
   * token is much shorter than in the original response.
   */
  static final String VALID_AWS_RESPONSE
      = "{"
      + " \"AssumedRoleUser\":"
      + "   {"
      + "    \"AssumedRole\": \"" + ASSUMED_ROLE + "\","
      + "    \"Arn\":         \"" + ARN + "\""
      + "   },"
      + " \"Credentials\":"
      + "   {"
      + "    \"SessionToken\":    \"" + SESSION_TOKEN + "\","
      + "    \"AccessKeyId\":     \"" + ACCESS_KEY + "\","
      + "    \"SecretAccessKey\": \"" + SECRET_ACCESS_KEY + "\","
      + "    \"Expiration\":      \"" + EXPIRATION + "\""
      + "   }"
      + "}";

  private final JsonSerialization<AuthResponseAWSMessage> serializer = AuthResponseAWSMessage.serializer();

  @Test
  public void testEmpty() throws IOException {
    AuthResponseAWSMessage message = serializer.fromJson("{}");

    assertNull(message.AssumedRoleUser);
    assertNull(message.Credentials);
  }

  @Test
  public void testNonEmpty() throws Throwable {
    JsonSerialization<AuthResponseAWSMessage> serializer = AuthResponseAWSMessage.serializer();
    AuthResponseAWSMessage responseAWSStruct = serializer.fromJson(VALID_AWS_RESPONSE);

    assertEquals(ASSUMED_ROLE, responseAWSStruct.AssumedRoleUser.AssumedRole);
    assertEquals(ARN, responseAWSStruct.AssumedRoleUser.Arn);
    assertEquals(ACCESS_KEY, responseAWSStruct.Credentials.AccessKeyId);
    assertEquals(SECRET_ACCESS_KEY, responseAWSStruct.Credentials.SecretAccessKey);
    assertEquals(SESSION_TOKEN, responseAWSStruct.Credentials.SessionToken);
    assertEquals(Long.parseLong(EXPIRATION), responseAWSStruct.Credentials.Expiration);
  }
}

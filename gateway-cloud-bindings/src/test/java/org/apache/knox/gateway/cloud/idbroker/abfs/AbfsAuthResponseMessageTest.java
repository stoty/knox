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

package org.apache.knox.gateway.cloud.idbroker.abfs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.apache.hadoop.util.JsonSerialization;
import org.junit.Test;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class AbfsAuthResponseMessageTest {

  private final JsonSerialization<AbfsAuthResponseMessage> serializer = AbfsAuthResponseMessage.serializer();

  @Test
  public void testEmpty() throws IOException {
    AbfsAuthResponseMessage message = serializer.fromJson("{}");

    assertNull(message.getAccessToken());
    assertNull(message.getResource());
    assertNull(message.getTokenType());
    assertNull(message.getExpiresIn());
    assertNull(message.getExpiresOn());
  }

  @Test
  public void testNonEmpty() throws IOException {

    AbfsAuthResponseMessage message = serializer.fromJson("{" +
        "  \"access_token\": \"eyJ0eXAiOiJKV1...Q\"," +
        "  \"expires_in\": \"28800\"," +
        "  \"expires_on\": \"1556247141\"," +
        "  \"resource\": \"https://storage.azure.com/\"," +
        "  \"token_type\": \"Bearer\"," +
        "  \"ignored_value\": \"This should be ignored\"" +  // Ignored value
        "}");

    assertEquals("eyJ0eXAiOiJKV1...Q", message.getAccessToken());
    assertEquals(Integer.valueOf(28800), message.getExpiresIn());
    assertEquals(Long.valueOf(1556247141L), message.getExpiresOn());
    assertEquals("https://storage.azure.com/", message.getResource());
    assertEquals("Bearer", message.getTokenType());
  }

  @Test
  public void testExpiresIn() throws IOException {

    AbfsAuthResponseMessage message = serializer.fromJson("{" +
        "  \"access_token\": \"eyJ0eXAiOiJKV1...Q\"," +
        "  \"expires_in\": \"28800\"," +
        "  \"resource\": \"https://storage.azure.com/\"," +
        "  \"token_type\": \"Bearer\"" +
        "}");

    // Use seconds since milliseconds may be too small of a unit for the test.
    assertEquals(System.currentTimeMillis() / 1000 + 28800, message.getExpiry().getEpochSecond());
  }

  @Test
  public void testExpiresOn() throws IOException {
    AbfsAuthResponseMessage message = serializer.fromJson("{" +
        "  \"access_token\": \"eyJ0eXAiOiJKV1...Q\"," +
        "  \"expires_on\": \"1556247141\"," +
        "  \"resource\": \"https://storage.azure.com/\"," +
        "  \"token_type\": \"Bearer\"" +
        "}");

    assertEquals(1556247141000L, message.getExpiry().toEpochMilli());
  }

  @Test
  public void testExpiresOnAndExpiresIn() throws IOException {
    AbfsAuthResponseMessage message = serializer.fromJson("{" +
        "  \"access_token\": \"eyJ0eXAiOiJKV1...Q\"," +
        "  \"expires_in\": \"28800\"," +
        "  \"expires_on\": \"1556247141\"," +
        "  \"resource\": \"https://storage.azure.com/\"," +
        "  \"token_type\": \"Bearer\"" +
        "}");

    // If expires_in and expires_on are both set, expires_on should be chosen...
    assertEquals(1556247141000L, message.getExpiry().toEpochMilli());
    assertEquals("2019-04-26T02:52:21Z", message.getExpiry().toString());
  }
}
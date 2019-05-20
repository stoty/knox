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

package org.apache.knox.gateway.cloud.idbroker.messages;

import static org.apache.knox.gateway.cloud.idbroker.messages.RequestDTResponseMessage.BEARER_TOKEN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.apache.hadoop.test.LambdaTestUtils;
import org.apache.hadoop.util.JsonSerialization;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;

public class RequestDTResponseMessageTest {

  private final JsonSerialization<RequestDTResponseMessage> serializer = new JsonSerialization<>(RequestDTResponseMessage.class, false, true);

  @Test
  public void testEmpty() throws Exception {
    RequestDTResponseMessage message = serializer.fromJson("{}");

    assertNull(message.access_token);
    assertNull(message.endpoint_public_cert);
    assertNull(message.target_url);
    assertNull(message.token_type);
    assertNull(message.expires_in);
    assertEquals(0, message.expiryTimeSeconds());

    LambdaTestUtils.intercept(IOException.class, message::validate);
  }

  @Test
  public void testNonEmpty() throws Exception {

    RequestDTResponseMessage message = serializer.fromJson("{" +
        "  \"access_token\": \"access_token\"," +
        "  \"endpoint_public_cert\": \"endpoint_public_cert\"," +
        "  \"expires_in\": \"28800000\"," +
        "  \"target_url\": \"target_url\"," +
        "  \"token_type\": \"token_type\"," +
        "  \"ignored_value\": \"This should be ignored\"" +  // Ignored value
        "}");

    assertEquals("access_token", message.access_token);
    assertEquals("endpoint_public_cert", message.endpoint_public_cert);
    assertEquals("target_url", message.target_url);
    assertEquals("token_type", message.token_type);
    assertEquals(BigInteger.valueOf(28800000), message.expires_in);
    assertEquals(28800L, message.expiryTimeSeconds());

    LambdaTestUtils.intercept(IOException.class, message::validate);

    // Fix token_type
    message.token_type = BEARER_TOKEN;
    message.validate();
  }

  @Test(expected = InvalidFormatException.class)
  public void testNonEmptyInvalidExpiresIn() throws IOException {

    RequestDTResponseMessage message = serializer.fromJson("{" +
        "  \"access_token\": \"access_token\"," +
        "  \"endpoint_public_cert\": \"endpoint_public_cert\"," +
        "  \"expires_in\": \"expires_in\"," +
        "  \"target_url\": \"target_url\"," +
        "  \"token_type\": \"Bearer\"," +
        "  \"ignored_value\": \"This should be ignored\"" +  // Ignored value
        "}");
  }

}
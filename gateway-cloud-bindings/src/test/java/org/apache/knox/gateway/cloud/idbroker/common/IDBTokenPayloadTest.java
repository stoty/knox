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

package org.apache.knox.gateway.cloud.idbroker.common;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.hadoop.io.DataOutputBuffer;
import org.apache.hadoop.test.LambdaTestUtils;
import org.apache.knox.gateway.util.Tokens;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;

public class IDBTokenPayloadTest {
  @Test
  public void testIDBTokenPayload() throws Exception {

    String expectedToken = "token";
    String expectedToken2 = "token2";
    String expectedEndpoint = "endpoint";
    long expectedExpiration = System.currentTimeMillis() / 1000 + 1000;
    long expectedExpiration2 = System.currentTimeMillis() / 1000 + 2000;
    long expectedIssueTime = System.currentTimeMillis();
    String expectedCorrelationId = "correlationId";
    String expectedEndpointCertificate = "endpointCertificate";
    String expectedEndpointCertificate2 = "endpointCertificate2";

    IDBTokenPayload payload;

    payload = new IDBTokenPayload(expectedToken, expectedEndpoint, expectedExpiration, expectedIssueTime, expectedCorrelationId, expectedEndpointCertificate);
    payload.validate(true);
    assertEquals(expectedToken, payload.getAccessToken());
    assertEquals(expectedEndpoint, payload.getEndpoint());
    assertEquals(expectedExpiration, payload.getExpiryTime());
    assertEquals(expectedEndpointCertificate, payload.getCertificate());

    Optional<OffsetDateTime> expiry = payload.getExpiryDateTime();
    assertTrue(expiry.isPresent());
    assertNotNull(expiry.get());
    assertEquals(expectedExpiration, expiry.get().toEpochSecond());

    DataOutputBuffer dataOutput = new DataOutputBuffer();
    payload.write(dataOutput);

    DataInput dataInput = new DataInputStream(new ByteArrayInputStream(dataOutput.getData()));

    IDBTokenPayload payload2 = new IDBTokenPayload();
    assertEquals("", payload2.getAccessToken());
    assertEquals("", payload2.getEndpoint());
    assertEquals(0, payload2.getExpiryTime());
    assertEquals("", payload2.getCertificate());
    assertNotEquals(payload, payload2);

    payload2.readFields(dataInput);
    assertEquals(expectedToken, payload2.getAccessToken());
    assertEquals(expectedEndpoint, payload2.getEndpoint());
    assertEquals(expectedExpiration, payload2.getExpiryTime());
    assertEquals(expectedEndpointCertificate, payload2.getCertificate());
    assertEquals(payload, payload2);

    payload.setAccessToken(expectedToken2);
    assertEquals(expectedToken2, payload.getAccessToken());

    payload.setExpiryTime(expectedExpiration2);
    assertEquals(expectedExpiration2, payload.getExpiryTime());

    payload.setCertificate(expectedEndpointCertificate2);
    assertEquals(expectedEndpointCertificate2, payload.getCertificate());

    Optional<OffsetDateTime> expiry2 = payload.getExpiryDateTime();
    assertTrue(expiry2.isPresent());
    assertNotNull(expiry2.get());
    assertEquals(expectedExpiration2, expiry2.get().toEpochSecond());

    payload.validate(true);

    payload.setCertificate("");
    payload.validate(false);

    LambdaTestUtils.intercept(IllegalStateException.class, ()->payload.validate(true));
  }

  @Test
  public void testToStringRedactedAccessToken() {
    final String expectedToken = "ThisIsMySecureTestAccessTokenWhichShouldBeRedacted";
    final String expectedEndpoint = "endpoint";
    final String expectedCorrelationId = "correlationId";
    final String expectedEndpointCertificate = "endpointCertificate";
    long expectedExpiration = System.currentTimeMillis() / 1000 + 1000;
    long expectedIssueTime = System.currentTimeMillis();

    IDBTokenPayload payload = new IDBTokenPayload(expectedToken,
                                                  expectedEndpoint,
                                                  expectedExpiration,
                                                  expectedIssueTime,
                                                  expectedCorrelationId,
                                                  expectedEndpointCertificate);

    Map<String, String> payloadString = TestUtils.parseTokenString(payload.toString());
    assertEquals("'" + Tokens.getTokenDisplayText(expectedToken) + "'", payloadString.get("accessToken"));
  }

}

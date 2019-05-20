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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.hadoop.io.DataOutputBuffer;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;

public class OAuthPayloadTest {

  @Test
  public void testOAuthPayload() throws IOException {

    String expectedToken = "token";
    long expectedExpiration = System.currentTimeMillis();

    OAuthPayload payload;

    payload = new OAuthPayload(expectedToken, expectedExpiration);
    assertFalse(payload.isEmpty());
    assertEquals(expectedToken, payload.getToken());
    assertEquals(expectedExpiration, payload.getExpiration());

    payload = new OAuthPayload();
    assertTrue(payload.isEmpty());
    payload.setToken(expectedToken);
    payload.setExpiration(expectedExpiration);
    assertFalse(payload.isEmpty());
    assertEquals(expectedToken, payload.getToken());
    assertEquals(expectedExpiration, payload.getExpiration());

    DataOutputBuffer dataOutput = new DataOutputBuffer();
    payload.write(dataOutput);

    DataInput dataInput = new DataInputStream(new ByteArrayInputStream(dataOutput.getData()));
    payload = new OAuthPayload();
    assertTrue(payload.isEmpty());
    payload.readFields(dataInput);
    assertFalse(payload.isEmpty());
    assertEquals(expectedToken, payload.getToken());
    assertEquals(expectedExpiration, payload.getExpiration());
  }
}
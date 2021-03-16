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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.knox.gateway.util.Tokens;
import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

public class KnoxTokenTest {

  private static final String DUMMY_TOKEN =
      "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYW50aG9zaCIsImF1ZCI6ImlkYnJva2VyIiwia" +
      "XNzIjoiS05PWFNTTyIsImV4cCI6MTU5OTEzOTE2NCwia25veC5pZCI6ImRiODQ5OTRiLWM" +
      "4MDAtNDA3NS1hN2VmLWNkZTNiZGNjZGEzMSJ9.YbEg6tQm6PWFzlOJU90b8ZKJyyTkvJcz" +
      "WKz95via-qybDhQ2yR_ZyWoEbcT93IAZIDbZFX1kdoEeBvDv_AyWKbNVzfmHNvOLvrVsId" +
      "QPiREgnw6rXX85PuwS5vhhduUU3DQFqCfkjy0altn0SKOVTW7flN8415pQnWvorNkTr87q" +
      "CjhyYIQg8ye-T2hPnsuyZ0vO42KoKcDIwu7xeBt-soT2prERt8zjuFA_sVdtwCBoTJPVl_" +
      "vRgZZ9NfWSfQUFzl62_6C7JZeBSkiCExPQz1LyFSQjJTIHHJuoGdsGWq4heHt-XiTGl3Id" +
      "j-r0ureA09ta8N1MCj3toXO38CwGr73u4uh10zAvR4OkHjMnCq5J-coSzNZWIk-Qnn5Tui" +
      "qPSU1xg-sonn4s9sB5cI38XAXSOizu3MGGbOPWmC9-LZv2efz1UG4qM0ELaspIOVmp1h1D" +
      "Z4b5EU1KOlbMkIuBcXMV7X9jJnWwT22D9V8UDJuaBLtZtA7y-hkWnOVdEQSC";

  @Test
  public void testKnoxTokenExpiration() {
    KnoxToken knoxToken;
    long expiry;

    // Expires in 1 minute
    expiry = Instant.now().plus(1, ChronoUnit.MINUTES).getEpochSecond();
    knoxToken = new KnoxToken("test", "test", expiry, "test", true);
    assertFalse(knoxToken.isExpired());
    assertFalse(knoxToken.isAboutToExpire(5));
    assertFalse(knoxToken.isAboutToExpire(30, ChronoUnit.SECONDS));
    assertTrue(knoxToken.isAboutToExpire(2, ChronoUnit.MINUTES));
    assertTrue(knoxToken.isAboutToExpire(1, ChronoUnit.MINUTES));

    // Expired 1 minute ago
    expiry = Instant.now().minus(1, ChronoUnit.MINUTES).getEpochSecond();
    knoxToken = new KnoxToken("test", "test", expiry, "test", true);
    assertTrue(knoxToken.isExpired());
    assertTrue(knoxToken.isAboutToExpire(5));
    assertTrue(knoxToken.isAboutToExpire(30, ChronoUnit.SECONDS));
    assertTrue(knoxToken.isAboutToExpire(2, ChronoUnit.MINUTES));
    assertTrue(knoxToken.isAboutToExpire(1, ChronoUnit.MINUTES));

    // Expires now
    expiry = Instant.now().getEpochSecond();
    knoxToken = new KnoxToken("test", "test", expiry, "test", true);
    assertTrue(knoxToken.isExpired());
    assertTrue(knoxToken.isAboutToExpire(5));
    assertTrue(knoxToken.isAboutToExpire(30, ChronoUnit.SECONDS));
    assertTrue(knoxToken.isAboutToExpire(2, ChronoUnit.MINUTES));
    assertTrue(knoxToken.isAboutToExpire(1, ChronoUnit.MINUTES));
  }

  @Test
  public void testGetPrintableAccessToken() {
    KnoxToken token =
          new KnoxToken("testOrigin", DUMMY_TOKEN, Instant.now().plus(1, ChronoUnit.MINUTES).getEpochSecond(), null, true);
    assertEquals(Tokens.getTokenDisplayText(DUMMY_TOKEN), token.getPrintableAccessToken());
  }

  @Test
  public void testToStringRedactedAccessToken() {
    doTestToString("test", DUMMY_TOKEN);
  }

  @Test
  public void testToStringMissingOrigin() {
    doTestToString(null, DUMMY_TOKEN);
  }

  private void doTestToString(final String origin,
                              final String accessToken) {
    final long   expiration = Instant.now().plus(1, ChronoUnit.MINUTES).getEpochSecond();
    final String publicCert = null;

    KnoxToken token = new KnoxToken(origin, accessToken, expiration, publicCert, true);
    assertNotNull(token);

    final Map<String, String> tokenString = TestUtils.parseTokenString(token.toString());
    assertEquals("Bearer", tokenString.get("TokenType"));
    assertEquals(getExpectedOrNullValue(origin), tokenString.get("origin"));
    assertEquals(getExpectedOrUnsetValue(publicCert), tokenString.get("endpointPublicCert"));
    assertEquals(String.valueOf(expiration), tokenString.get("expiry"));
    assertEquals(Tokens.getTokenDisplayText(DUMMY_TOKEN), tokenString.get("accessToken"));
  }

  private static String getExpectedOrNullValue(final String expectedValue) {
    return expectedValue != null ? expectedValue : "null";
  }

  private static String getExpectedOrUnsetValue(final String expectedValue) {
    return expectedValue != null ? expectedValue : "<unset>";
  }

}

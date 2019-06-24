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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class KnoxTokenTest {

  @Test
  public void testKnoxTokenExpiration() {
    KnoxToken knoxToken;
    long expiry;

    // Expires in 1 minute
    expiry = Instant.now().plus(1, ChronoUnit.MINUTES).getEpochSecond();
    knoxToken = new KnoxToken("test", "test", expiry, "test");
    assertFalse(knoxToken.isExpired());
    assertFalse(knoxToken.isAboutToExpire(5));
    assertFalse(knoxToken.isAboutToExpire(30, ChronoUnit.SECONDS));
    assertTrue(knoxToken.isAboutToExpire(2, ChronoUnit.MINUTES));
    assertTrue(knoxToken.isAboutToExpire(1, ChronoUnit.MINUTES));

    // Expired 1 minute ago
    expiry = Instant.now().minus(1, ChronoUnit.MINUTES).getEpochSecond();
    knoxToken = new KnoxToken("test", "test", expiry, "test");
    assertTrue(knoxToken.isExpired());
    assertTrue(knoxToken.isAboutToExpire(5));
    assertTrue(knoxToken.isAboutToExpire(30, ChronoUnit.SECONDS));
    assertTrue(knoxToken.isAboutToExpire(2, ChronoUnit.MINUTES));
    assertTrue(knoxToken.isAboutToExpire(1, ChronoUnit.MINUTES));

    // Expires now
    expiry = Instant.now().getEpochSecond();
    knoxToken = new KnoxToken("test", "test", expiry, "test");
    assertTrue(knoxToken.isExpired());
    assertTrue(knoxToken.isAboutToExpire(5));
    assertTrue(knoxToken.isAboutToExpire(30, ChronoUnit.SECONDS));
    assertTrue(knoxToken.isAboutToExpire(2, ChronoUnit.MINUTES));
    assertTrue(knoxToken.isAboutToExpire(1, ChronoUnit.MINUTES));
  }

}
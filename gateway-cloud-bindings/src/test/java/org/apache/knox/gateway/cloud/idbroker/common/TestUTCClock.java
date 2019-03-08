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

import java.time.OffsetDateTime;
import java.util.Optional;

import org.junit.Test;

import org.apache.hadoop.test.HadoopTestBase;

import static org.apache.knox.gateway.cloud.idbroker.common.UTCClock.*;

/**
 * Test for UTC clock operations, especially handling of empty values,
 * the second/milli conversion logic, and the {@link UTCClock#hasExpired(OffsetDateTime)}
 * operation.
 */
public class TestUTCClock extends HadoopTestBase {

  private final UTCClock clock = getClock();

  private void assertPresent(final Optional<OffsetDateTime> dt0) {
    assertNotEquals(Optional.empty(), dt0);
  }

  private void assertNotPresent(final Optional<OffsetDateTime> dt0) {
    assertEquals(Optional.empty(), dt0);
  }

  private void assertHasExpired(final Optional<OffsetDateTime> dt0) {
    assertTrue("Has not expired " + dt0, clock.hasExpired(dt0));
  }

  @Test
  public void testCurrentTimeMillis() throws Throwable {
    long t0 = clock.getCurrentTimeInMillis();
    assertTrue(t0 > 0);
    Optional<OffsetDateTime> dt0 = millisToDateTime(t0);
    assertPresent(dt0);
    assertEquals(t0, dt0.get().toInstant().toEpochMilli());
  }

  @Test
  public void testExpiredTimeMillis() throws Throwable {
    long t0 = clock.getCurrentTimeInMillis() - 60_000;
    assertTrue(t0 > 0);
    Optional<OffsetDateTime> dt0 = millisToDateTime(t0);
    assertPresent(dt0);
    assertHasExpired(dt0);
  }

  @Test
  public void testExpiredTimeSeconds() throws Throwable {
    long t0 = (clock.getCurrentTimeInMillis() - 180_000) / 1000;
    assertTrue(t0 > 0);
    Optional<OffsetDateTime> dt0 = secondsToDateTime(t0);
    assertPresent(dt0);
    assertHasExpired(dt0);
  }

  @Test
  public void testEpoch0() throws Throwable {
    Optional<OffsetDateTime> dt0 = millisToDateTime(0);
    assertNotPresent(dt0);
    assertEquals(NO_DATE_TIME, timeToString(dt0));
    Optional<OffsetDateTime> dt1 = secondsToDateTime(0);
    assertEquals(dt0, dt1);
    assertEquals(NO_DATE_TIME, secondsToString(0));
    assertHasExpired(dt0);
  }

  @Test
  public void testCurrentTime() throws Throwable {
    OffsetDateTime dt0 = clock.getCurrentTime();
    OffsetDateTime dt1 = dt0.plusDays(1);
    assertFalse("Has expired " + dt1, clock.hasExpired(dt1));
  }
}

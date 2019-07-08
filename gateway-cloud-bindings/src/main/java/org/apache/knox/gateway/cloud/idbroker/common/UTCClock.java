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

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Optional;
import java.util.TimeZone;

/**
 * Clock that gives the current UTC time in milliseconds
 * and some operations to work on it.
 *
 * Derived from the YARN UTCClock.
 */
public class UTCClock {
  /**
   * Text value you get when there is no date or time: {@value}.
   */
  public static final String NO_DATE_TIME = "none";

  private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

  private static final UTCClock clock = new UTCClock();

  private UTCClock() {
    // Force static methods
  }

  public static UTCClock getClock() {
    return clock;
  }

  /**
   * Get the current UTC time in milliseconds since the epoch.
   * @return a time.
   */
  public long getCurrentTimeInMillis() {
    // Need to use a new Calendar instance each time since Calendar is a point in time
    return Calendar.getInstance(UTC).getTimeInMillis();
  }

  /**
   * Get the current time in a java 8 time type.
   * @return the current time in UTC.
   */
  @SuppressWarnings("OptionalGetWithoutIsPresent")
  public OffsetDateTime getCurrentTime() {
    return millisToDateTime(getCurrentTimeInMillis()).get();
  }

  /**
   * Is a time in the past?
   * @param dateTime time to examine.
   * @return true if the time is a past time
   */
  public boolean hasExpired(OffsetDateTime dateTime) {
    return dateTime.compareTo(getCurrentTime()) < 0;
  }

  /**
   * Is a time in the past?
   * @param dateTime time to examine.
   * @return true if the time is a past time or not set.
   */
  public boolean hasExpired(Optional<OffsetDateTime> dateTime) {
    return dateTime.map(this::hasExpired).orElse(true);
  }

  /**
   * Convert a time in seconds to a string.
   * @param timeInSeconds the time in seconds.
   * @return a string value in the ISO Date Time format.
   */
  public static String secondsToString(long timeInSeconds) {
    return timeToString(secondsToDateTime(timeInSeconds));
  }

  /**
   * Convert an optional time to a string.
   * If the time is empty, it is mapped to the value {@link #NO_DATE_TIME}
   * @param dateTime the time.
   * @return a string value in the ISO Date Time format.
   */
  public static String timeToString(Optional<OffsetDateTime> dateTime) {
    return dateTime
        .map(x -> x.format(DateTimeFormatter.ISO_DATE_TIME))
        .orElse(NO_DATE_TIME);
  }

  /**
   * Get a temporal representing the time of expiration, if there
   * is one.
   * If the time is 0, it is mapped to the empty option.
   * This is here to wrap up expectations about timestamps and zones.
   * @return the expiration time, if not zero
   */
  public static Optional<OffsetDateTime> secondsToDateTime(long seconds) {
    return seconds == 0
        ? Optional.empty()
        : Optional.of(
            OffsetDateTime.ofInstant(
                Instant.ofEpochSecond(seconds),
                ZoneOffset.UTC));
  }

  /**
   * Get a temporal representing the time of expiration, if there
   * is one.
   * If the time is 0, it is mapped to the empty option.
   * This is here to wrap up expectations about timestamps and zones.
   * @return the expiration time, if not zero
   */
  public static Optional<OffsetDateTime> millisToDateTime(long millis) {
    return millis == 0
        ? Optional.empty()
        : Optional.of(
            OffsetDateTime.ofInstant(
                Instant.ofEpochMilli(millis),
                ZoneOffset.UTC));
  }

}

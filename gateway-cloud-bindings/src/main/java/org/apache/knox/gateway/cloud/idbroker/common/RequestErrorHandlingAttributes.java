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
package org.apache.knox.gateway.cloud.idbroker.common;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.Range;

public class RequestErrorHandlingAttributes {

  private static final Range<Integer> VALID_FAILOVER_ATTEMPT_RANGE = Range.between(2, 20);
  private static final Range<Integer> VALID_FAILOVER_SLEEP_RANGE = Range.between(1, 5);
  private static final Range<Integer> VALID_RETRY_ATTEMPT_RANGE = Range.between(2, 20);
  private static final Range<Integer> VALID_RETRY_SLEEP_RANGE = Range.between(5, 10);
  private static final String ERROR_MSG_TEMPLATE = "%s = %d is not in %s";

  private final int maxFailoverAttempts;
  private final int failoverSleep;
  private final int maxRetryAttempts;
  private final int retrySleep;

  public RequestErrorHandlingAttributes(int maxFailoverAttempts, int failoverSleep, int maxRetryAttempts, int retrySleep) {
    this.maxFailoverAttempts = maxFailoverAttempts;
    this.failoverSleep = failoverSleep;
    this.maxRetryAttempts = maxRetryAttempts;
    this.retrySleep = retrySleep;
    validate();
  }

  private void validate() {
    final Set<String> errors = new LinkedHashSet<>();
    check(maxFailoverAttempts, VALID_FAILOVER_ATTEMPT_RANGE, "maxFailoverAttempts", errors);
    check(failoverSleep, VALID_FAILOVER_SLEEP_RANGE, "failoverSleep", errors);
    check(maxRetryAttempts, VALID_RETRY_ATTEMPT_RANGE, "maxRetryAttempts", errors);
    check(retrySleep, VALID_RETRY_SLEEP_RANGE, "retrySleep", errors);
    if (!errors.isEmpty()) {
      throw new IllegalArgumentException("Found validation error(s): " + String.join("; ", errors));
    }
  }

  private void check(int value, Range<Integer> range, String attributeName, Set<String> errors) {
    if (!range.contains(value)) {
      errors.add(String.format(Locale.ROOT, ERROR_MSG_TEMPLATE, attributeName, value, range.toString()));
    }
  }

  public int getMaxFailoverAttempts() {
    return maxFailoverAttempts;
  }

  public long getFailoverSleepInMillis() {
    return TimeUnit.SECONDS.toMillis(failoverSleep);
  }

  public int getMaxRetryAttempts() {
    return maxRetryAttempts;
  }

  public long getRetrySleepInMillis() {
    return TimeUnit.SECONDS.toMillis(retrySleep);
  }

}

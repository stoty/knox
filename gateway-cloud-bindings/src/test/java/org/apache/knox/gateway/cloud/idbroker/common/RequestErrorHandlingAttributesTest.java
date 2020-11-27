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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class RequestErrorHandlingAttributesTest {
  private final int validMaxFailoverAttempts = 7; // within the range
  private final int validFailoverSleep = 1; // =lower bound
  private final int validMaxRetryAttempts = 10; // =upper bound
  private final int validRetrySleep = 8; // within the range

  private final int invalidMaxFailoverAttempts = 1; // under lower bound
  private final int invalidFailoverSleep = 6; // above upper bound
  private final int invalidMaxRetryAttempts = 11; // above upper bound
  private final int invalidRetrySleep = 4; // under lower bound

  @Rule
  public ExpectedException expectedEx = ExpectedException.none();

  @Test
  public void shouldPassValidationIfCorrectValuesAreSet() throws Exception {
    new RequestErrorHandlingAttributes(validMaxFailoverAttempts, validFailoverSleep, validMaxRetryAttempts, validRetrySleep);
  }

  @Test
  public void shouldNotPassValidationIfIncorrectValuesAreSet() throws Exception {
    expectedEx.expect(IllegalArgumentException.class);
    expectedEx.expectMessage(
        "Found validation error(s): maxFailoverAttempts = 1 is not in [2..10]; failoverSleep = 6 is not in [1..5]; maxRetryAttempts = 11 is not in [2..10]; retrySleep = 4 is not in [5..10]");
    new RequestErrorHandlingAttributes(invalidMaxFailoverAttempts, invalidFailoverSleep, invalidMaxRetryAttempts, invalidRetrySleep);
  }

  @Test
  public void shouldNotPassValidationIfIncorrectMaxFailoverAttemptsValueIsSet() throws Exception {
    expectedEx.expect(IllegalArgumentException.class);
    expectedEx.expectMessage("Found validation error(s): maxFailoverAttempts = 1 is not in [2..10]");
    new RequestErrorHandlingAttributes(invalidMaxFailoverAttempts, validFailoverSleep, validMaxRetryAttempts, validRetrySleep);
  }

  @Test
  public void shouldNotPassValidationIfIncorrectFailoverSleepValueIsSet() throws Exception {
    expectedEx.expectMessage("Found validation error(s): failoverSleep = 6 is not in [1..5]");
    new RequestErrorHandlingAttributes(validMaxFailoverAttempts, invalidFailoverSleep, validMaxRetryAttempts, validRetrySleep);
  }

  @Test
  public void shouldNotPassValidationIfIncorrectMaxRetryAttemptsValueIsSet() throws Exception {
    expectedEx.expectMessage("Found validation error(s): maxRetryAttempts = 11 is not in [2..10]");
    new RequestErrorHandlingAttributes(validMaxFailoverAttempts, validFailoverSleep, invalidMaxRetryAttempts, validRetrySleep);
  }

  @Test
  public void shouldNotPassValidationIfIncorrectRetrySleepValueIsSet() throws Exception {
    expectedEx.expectMessage("Found validation error(s): retrySleep = 4 is not in [5..10]");
    new RequestErrorHandlingAttributes(validMaxFailoverAttempts, validFailoverSleep, validMaxRetryAttempts, invalidRetrySleep);
  }

}

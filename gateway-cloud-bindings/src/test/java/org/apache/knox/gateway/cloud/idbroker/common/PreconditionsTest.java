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

import org.junit.Test;

public class PreconditionsTest {

  @Test
  public void testCheckNotNullWithNonNull() {
    String value = "some value";
    assertEquals(value, Preconditions.checkNotNull(value));
  }

  @Test(expected = NullPointerException.class)
  public void testCheckNotNullWithNull() {
    String value = null;
    Preconditions.checkNotNull(value);
  }

  @Test
  public void testCheckNotNullWithNonNullWithMessage() {
    String value = "some value";
    String message = "Some message";
    assertEquals(value, Preconditions.checkNotNull(value, message));
  }

  @Test(expected = NullPointerException.class)
  public void testCheckNotNullWithNullWithMessage() {
    String value = null;
    String message = "Some message";
    try {
      Preconditions.checkNotNull(value, message);
    } catch (NullPointerException e) {
      assertEquals(message, e.getMessage());
      throw e;
    }
  }

  @Test
  public void testCheckArgumentSuccess() {
    boolean value = true;
    String message = "Some message";
    Preconditions.checkArgument(value, message);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testCheckArgumentFail() {
    boolean value = false;
    String message = "Some message";
    try {
      Preconditions.checkArgument(value, message);
    } catch (IllegalArgumentException e) {
      assertEquals(message, e.getMessage());
      throw e;
    }
  }

  @Test
  public void testCheckArgumentSuccessWithMessageTemplate() {
    boolean value = true;
    String messageTemplate = "Some message: %s";
    Preconditions.checkArgument(value, messageTemplate, value);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testCheckArgumentFailWithMessageTemplate() {
    boolean value = false;
    String messageTemplate = "Some message: %s";
    try {
      Preconditions.checkArgument(value, messageTemplate, value);
    } catch (IllegalArgumentException e) {
      assertEquals("Some message: false", e.getMessage());
      throw e;
    }
  }

  @Test
  public void testCheckStateSuccess() {
    Preconditions.checkState(true);
  }

  @Test(expected = IllegalStateException.class)
  public void testCheckStateFail() {
    Preconditions.checkState(false);
  }

  @Test
  public void testCheckStateSuccessWithMessage() {
    boolean value = true;
    String message = "Some message";
    Preconditions.checkState(value, message);
  }

  @Test(expected = IllegalStateException.class)
  public void testCheckStateFailWithMessage() {
    boolean value = false;
    String message = "Some message";
    try {
      Preconditions.checkState(value, message);
    } catch (IllegalStateException e) {
      assertEquals(message, e.getMessage());
      throw e;
    }
  }

  @Test
  public void testCheckStateSuccessWithMessageTemplate() {
    boolean value = true;
    String messageTemplate = "Some message: %s";
    Preconditions.checkState(value, messageTemplate, value);
  }

  @Test(expected = IllegalStateException.class)
  public void testCheckStateFailWithMessageTemplate() {
    boolean value = false;
    String messageTemplate = "Some message: %s";
    try {
      Preconditions.checkState(value, messageTemplate, value);
    } catch (IllegalStateException e) {
      assertEquals("Some message: false", e.getMessage());
      throw e;
    }
  }
}
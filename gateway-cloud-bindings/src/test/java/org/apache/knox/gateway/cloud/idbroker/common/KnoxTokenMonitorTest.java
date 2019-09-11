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

import org.junit.Test;

import java.util.concurrent.ThreadFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class KnoxTokenMonitorTest {

  @Test
  @SuppressWarnings({"PMD.DoNotUseThreads"})
  public void testMonitorThreadFactory() {
    ThreadFactory tf = new KnoxTokenMonitor.MonitorThreadFactory();
    Thread t1 = tf.newThread(() -> { });
    assertNotNull("Expected a Thread object from the monitor thread factory", t1);
    assertTrue("Expected the monitor thread to be a daemon thread.", t1.isDaemon());
    assertEquals("KnoxTokenMonitor-1", t1.getName());

    Thread t2 = tf.newThread(() -> { });
    assertNotNull("Expected a Thread object from the monitor thread factory", t2);
    assertTrue("Expected the monitor thread to be a daemon thread.", t2.isDaemon());
    assertEquals("KnoxTokenMonitor-2", t2.getName());
  }

}

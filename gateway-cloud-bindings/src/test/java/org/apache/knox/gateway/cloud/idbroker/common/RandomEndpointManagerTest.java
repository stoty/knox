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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotEquals;

public class RandomEndpointManagerTest {

  @Test
  public void testRandomEndpointManager() {
    String[] endpoints = new String[]{ "https://host1:8443/gateway",
                                       "https://host2:8443/gateway",
                                       "https://host3:8443/gateway/",
                                       "https://host4:8443/gateway/",
                                       "https://host5:8443/gateway/" };
    assertNotEquals(new RandomEndpointManager(Arrays.asList(endpoints)).getActiveURL(),
                    new RandomEndpointManager(Arrays.asList(endpoints)).getActiveURL());
  }

  /**
   * This test is just for peace of mind that the randomness for only 2 endpoints is sufficient.
   */
  @Test
  public void testRandomEndpointManagerWithOnlyTwoEndpoints() {
    String[] endpoints = new String[]{ "https://host1:8443/gateway", "https://host2:8443/gateway"};
    Map<String, Integer> results = new HashMap<>();
    for (String endpoint : endpoints) {
      results.put(endpoint, 0);
    }

    for (int i = 0; i < 1000; i++) {
      String endpoint = new RandomEndpointManager(Arrays.asList(endpoints)).getActiveURL();
      results.put(endpoint, results.get(endpoint) + 1);
    }

    for (String endpoint : results.keySet()) {
      System.out.println(endpoint + " : " + results.get(endpoint));
    }
  }

}

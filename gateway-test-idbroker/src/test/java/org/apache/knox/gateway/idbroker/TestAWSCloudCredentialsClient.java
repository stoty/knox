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
package org.apache.knox.gateway.idbroker;

import org.apache.knox.gateway.service.idbroker.aws.KnoxAWSClient;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class TestAWSCloudCredentialsClient extends KnoxAWSClient {
  private static final Map<String, Object> roleCredentials = new HashMap<>();

  public static final List<TestAWSCloudCredentialsClient> instances = new ArrayList<>();

  static final String NAME = "AWSTest";

  static void setRoleCredential(String role, Object credential) {
    roleCredentials.put(role, credential);
  }

  static Object getRoleCredential(String role) {
    return roleCredentials.get(role);
  }

  @Override
  public void init(Properties context) {
    super.init(context);
    TestAWSCloudCredentialsClient.instances.add(this);
  }

  @Override
  public String getName() {
    return NAME;
  }

  public String getConfiguredRegionName() {
    return this.regionName;
  }

  public int getConfiguredTokenLifetime() {
    return this.tokenLifetime;
  }

  @Override
  public Object getCredentialsForRole(String role) {
    return roleCredentials.get(role);
  }
}

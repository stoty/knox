/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.service.idbroker;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class DefaultCloudClientConfiguration implements CloudClientConfiguration {

  private static final String USER_ROLE_PROPERTY_PREFIX  = "role.user.";
  private static final String GROUP_ROLE_PROPERTY_PREFIX = "role.group.";

  private Map<String, Object> properties = new HashMap<>();


  @Override
  public Set<String> getPropertyNames() {
    return properties.keySet();
  }

  @Override
  public Object getProperty(String name) {
    return properties.get(name);
  }

  public void setProperty(String propertyName, Object propertyValue) {
    properties.put(propertyName, propertyValue);
  }


  @Override
  public String getUserRole(String user) {
    return (String) getProperty(USER_ROLE_PROPERTY_PREFIX + user);
  }

  @Override
  public String getGroupRole(String group) {
    return (String) getProperty(GROUP_ROLE_PROPERTY_PREFIX + group);
  }

}

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

import org.apache.knox.gateway.config.GatewayConfig;

import java.util.Locale;
import java.util.Properties;

import static org.apache.knox.gateway.service.idbroker.KnoxCloudCredentialsClientManager.CLOUD_CLIENT_PROVIDER;

public class DefaultCloudClientConfiguration implements CloudClientConfiguration {
  private static final String IDBROKER_PREFIX = "idbroker.";
  private static final String USER_ROLE_PROPERTY_PREFIX  = "role.user.";
  private static final String GROUP_ROLE_PROPERTY_PREFIX = "role.group.";
  private static final String USER_DEFAULT_GROUP_PREFIX  = "group.user.";

  private static final String USER_DEFAULT_MAPPING_SUFFIX  = ".user.default.role.mapping";
  private static final String USER_ROLE_MAPPING_SUFFIX  = ".user.role.mapping";
  private static final String GROUP_ROLE_MAPPING_SUFFIX = ".group.role.mapping";

  private final Properties properties;
  private final GatewayConfig config;
  private final String configPrefix;

  DefaultCloudClientConfiguration(GatewayConfig config, Properties context) {
    this.config = config;
    this.properties = context;

    String cloudProviderType = context.getProperty(CLOUD_CLIENT_PROVIDER);
    if(cloudProviderType != null) {
      configPrefix = IDBROKER_PREFIX + cloudProviderType.toLowerCase(Locale.ROOT);
    } else {
      configPrefix = "";
    }
  }

  @Override
  public String getProperty(String name) {
    String property = (String)properties.get(name);
    if(property == null && config != null) {
      return config.get(name);
    }
    return property;
  }

  public void setProperty(String propertyName, String propertyValue) {
    properties.put(propertyName, propertyValue);
  }

  @Override
  public String getUserRole(String user) {
    String role = getProperty(USER_ROLE_PROPERTY_PREFIX + user);
    if(role == null) {
      String userRoleMapping = getProperty(configPrefix + USER_ROLE_MAPPING_SUFFIX);
      return parseMappingProperties(userRoleMapping, user);
    }
    return role;
  }

  @Override
  public String getGroupRole(String group) {
    String role = getProperty(GROUP_ROLE_PROPERTY_PREFIX + group);
    if(role == null) {
      String groupRoleMapping = getProperty(configPrefix + GROUP_ROLE_MAPPING_SUFFIX);
      return parseMappingProperties(groupRoleMapping, group);
    }
    return role;
  }

  @Override
  public String getDefaultGroupForUser(String user) {
    String group = getProperty(USER_DEFAULT_GROUP_PREFIX + user);
    if(group == null) {
      String defaultUserRoleMapping = getProperty(configPrefix + USER_DEFAULT_MAPPING_SUFFIX);
      return parseMappingProperties(defaultUserRoleMapping, user);
    }
    return group;
  }

  private String parseMappingProperties(String mappings, String key) {
    Properties properties = new Properties();
    if(mappings != null) {
      for(String rolePair : mappings.split(";")) {
        String[] rolePairParts = rolePair.split("=",2);
        String id = rolePairParts[0];
        String role = rolePairParts[1];
        properties.put(id, role);
      }
    }
    return properties.getProperty(key);
  }
}

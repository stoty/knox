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


import java.util.Set;

public interface CloudClientConfiguration {

  /**
   * Get all the configuration property names
   */
  Set<String> getPropertyNames();


  /**
   * Get the value for the specified configuration property name
   */
  Object getProperty(String name);

  /**
   * Get the role mapped for the specified user identifier
   *
   * @param user The user identifier
   *
   * @return The role mapped to the user, or null if none has been configured
   */
  String getUserRole(String user);

  /**
   * Get the role mapped for the specified group identifier
   *
   * @param group The group identifier
   *
   * @return The role mapped to the group, or null if none has been configured
   */
  String getGroupRole(String group);

  /**
   * Get the configured default group for the specified user identifier
   *
   * @param user The user identifier
   *
   * @return The configured default group, or null if none has been configured
   */
  String getDefaultGroupForUser(String user);

}

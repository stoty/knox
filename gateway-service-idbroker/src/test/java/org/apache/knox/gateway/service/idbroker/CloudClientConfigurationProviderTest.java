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

import org.junit.Test;

import java.util.Properties;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNull;
import static org.junit.Assert.assertNotNull;


public class CloudClientConfigurationProviderTest {

  @Test
  public void testDefaultConfigProviderWithNullContext() {
    CloudClientConfigurationProviderManager mgr = new CloudClientConfigurationProviderManager();
    mgr.init(null);
    assertEquals("Default", mgr.getName());
    assertNull(mgr.getConfig());
  }

  @Test
  public void testDefaultConfigProviderWithNoProperties() {
    CloudClientConfigurationProviderManager mgr = new CloudClientConfigurationProviderManager();
    Properties context = new Properties();
    mgr.init(context);
    assertEquals("Default", mgr.getName());
    CloudClientConfiguration config = mgr.getConfig();
    assertNotNull(config);
  }

  @Test
  public void testDefaultConfigProvider() {
    CloudClientConfigurationProviderManager mgr = new CloudClientConfigurationProviderManager();
    Properties context = new Properties();
    context.setProperty("aws.region.name", "us_east_2");
    context.setProperty("role.user.test", "someRole");
    context.setProperty("role.user.admin", "adminRole");
    context.setProperty("role.group.admin", "adminRole");
    context.setProperty("role.group.audit", "readOnlyRole");
    context.setProperty("role.group.test", "limitedWriteRole");
    context.setProperty("credential.cache.ttl", "1200");
    mgr.init(context);
    assertEquals("Default", mgr.getName());
    CloudClientConfiguration config = mgr.getConfig();
    assertNotNull(config);

    // Validate the contents
    assertEquals("us_east_2", config.getProperty("aws.region.name"));
    assertEquals("someRole", config.getProperty("role.user.test"));
    assertEquals("1200", config.getProperty("credential.cache.ttl"));
    assertEquals("someRole", config.getUserRole("test"));
    assertEquals("adminRole", config.getUserRole("admin"));
    assertNull(config.getUserRole("ijustmadethisup"));
    assertEquals("limitedWriteRole", config.getGroupRole("test"));
    assertEquals("readOnlyRole", config.getGroupRole("audit"));
    assertEquals("adminRole", config.getGroupRole("admin"));
    assertNull(config.getGroupRole("notaconfiguredgroup"));
  }

  @Test
  public void testInvalidExplicitProvider() {
    CloudClientConfigurationProviderManager mgr = new CloudClientConfigurationProviderManager();
    Properties context = new Properties();
    context.setProperty("cloud.policy.config.provider", "myProvider");
    mgr.init(context);
    assertEquals("myProvider", mgr.getName());
    CloudClientConfiguration config = mgr.getConfig();
    assertNull(config); // no config because the provider is invalid
  }

}

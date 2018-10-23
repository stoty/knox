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
package org.apache.knox.gateway.service.idbroker;

import java.util.Properties;
import java.util.ServiceLoader;


public class CloudClientConfigurationProviderManager implements CloudClientConfigurationProvider {

  private static final String DEFAULT_CLOUD_POLICY_CONFIG_PROVIDER = "Default";
  private static final String CLOUD_POLICY_CONFIG_PROVIDER = "cloud.policy.config.provider";

  private Properties properties = new Properties();
  private CloudClientConfigurationProvider delegate = null;

  @Override
  public void init(Properties context) {
    if (context != null) {
      properties.putAll(context);
      try {
        delegate = loadDelegate(context.getProperty(CLOUD_POLICY_CONFIG_PROVIDER,
                                                    DEFAULT_CLOUD_POLICY_CONFIG_PROVIDER));
        delegate.init(context);
      } catch (IdentityBrokerConfigException e) {
        e.printStackTrace(); // TODO: Logging
      }
    }
  }

  @Override
  public String getName() {
    return properties.getProperty(CLOUD_POLICY_CONFIG_PROVIDER, DEFAULT_CLOUD_POLICY_CONFIG_PROVIDER);
  }

  @Override
  public CloudClientConfiguration getConfig() {
    CloudClientConfiguration config = null;
    if (delegate != null) {
      config = delegate.getConfig();
    }
    return config;
  }



  private CloudClientConfigurationProvider loadDelegate(String name) throws IdentityBrokerConfigException {
    CloudClientConfigurationProvider delegate = null;

    ServiceLoader<CloudClientConfigurationProvider> loader = ServiceLoader.load(CloudClientConfigurationProvider.class);
    for (CloudClientConfigurationProvider configProvider : loader) {
      if (name.equalsIgnoreCase(configProvider.getName())) {
        delegate = configProvider;
        break;
      }
    }

    if (delegate == null) {
      throw new IdentityBrokerConfigException("Unable to load client identified by: " + name);
    }

    return delegate;
  }

}

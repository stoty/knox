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
package org.apache.knox.gateway.cloud.idbroker.google;

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.common.CommonUtils;
import org.apache.knox.gateway.cloud.idbroker.common.Preconditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.CONFIG_CLIENT_IMPL;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.DEFAULT_CONFIG_CAB_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.DEFAULT_CONFIG_CAB_PATH;

final class CABUtils {

  private static final Logger LOG = LoggerFactory.getLogger(CABUtils.class);

  private CABUtils() {
  }

  static IDBClient<AccessTokenProvider.AccessToken> newClient(Configuration conf, UserGroupInformation owner) {
    IDBClient<AccessTokenProvider.AccessToken> client = null;

    String clientImpl = conf.get(CONFIG_CLIENT_IMPL);
    if (clientImpl != null) {
      try {
        Class<?> clazz = Class.forName(clientImpl, false, Thread.currentThread().getContextClassLoader());
        Constructor<?> ctor = clazz.getConstructor(Configuration.class);
        Object instance = ctor.newInstance(conf);
        if (!IDBClient.class.isAssignableFrom(instance.getClass())) {
          throw new IllegalArgumentException(clientImpl + " is not a IDBClient<AccessTokenProvider.AccessToken> implementation.");
        }
        client = (IDBClient<AccessTokenProvider.AccessToken>) instance;
      } catch (Exception e) {
        LOG.error("Failed to instantiate the configured IDBClient implementation {} : {}",
                  clientImpl,
                  e.getMessage());
      }
    }

    if (client == null) {
      LOG.debug("Using the default CloudAccessBrokerClient");
      try {
        client = new GoogleIDBClient(conf, owner);
      } catch (IOException e) {
        LOG.error(e.getMessage());
      }
    }

    return client;
  }


  static void setCloudAccessBrokerAddresses(final Configuration conf, final String...endpoints) {
    final String endpointDelimiter = ",";

    // Construct the config property value
    String endpointConfigValue = "";
    for (int i = 0; i < endpoints.length; i++) {
      endpointConfigValue += endpoints[i];
      if (i < endpoints.length - 1) {
        endpointConfigValue += endpointDelimiter;
      }
    }

    // Set the value on the Configuration object
    conf.set(CONFIG_CAB_ADDRESS, endpointConfigValue);
  }

  /**
   * Get the URL(s) of the CloudAccessBroker
   * @param conf configuration to scan
   * @return the address, with any trailing / stripped
   * @throws IllegalArgumentException if there is none
   */
  static List<String> getCloudAccessBrokerAddresses(final Configuration conf)
      throws IllegalArgumentException{
    List<String> addresses = new ArrayList<>();
    String[] configuredValues = conf.getStrings(CONFIG_CAB_ADDRESS);
    Preconditions.checkArgument((configuredValues.length == 0), "No URL(s) provided in %s", CONFIG_CAB_ADDRESS);
    for (String address : configuredValues) {
      addresses.add(address.trim());
    }
    return addresses;
  }


  static String getCloudAccessBrokerURL(final Configuration conf, final String endpoint) {
    Preconditions.checkArgument(!StringUtils.isBlank(endpoint), "Invalid endpoint address.");
    return getBrokerURL(conf, endpoint, CONFIG_CAB_PATH, DEFAULT_CONFIG_CAB_PATH);
  }


  static String getDelegationTokenProviderURL(final Configuration conf, final String endpoint) {
    Preconditions.checkArgument(!StringUtils.isBlank(endpoint), "Invalid endpoint address.");
    return getBrokerURL(conf, endpoint, CONFIG_CAB_DT_PATH, DEFAULT_CONFIG_CAB_DT_PATH);
  }

  /**
   * Get the URL to a broker component.
   * @param conf configuration to read.
   * @param baseEndpoint base endpoint address.
   * @param key key to the specific path
   * @param defVal default value
   * @return the full URL to the service
   * @throws IllegalArgumentException bad configuration.
   */
  static String getBrokerURL(final Configuration conf,
                             final String baseEndpoint,
                             final String key,
                             final String defVal) {
    String v = conf.getTrimmed(key, defVal);
    Preconditions.checkArgument(!v.isEmpty(), "No path in %s", key);
    return constructURL(baseEndpoint, v);
  }

  /**
   * Combine an address and path; guarantee that there is exactly one "/"
   * between the two.
   * @param address address
   * @param path path underneath
   * @return a concatenation of the address +"/" + path
   */
  public static String constructURL(final String address, final String path) {
    String url = null;
    if (StringUtils.isNotEmpty(address) && StringUtils.isNotEmpty(path)) {
      String a = address;
      if (a.endsWith("/")) {
        a = a.substring(0, a.length() - 1);
      }
      url = a + (!path.startsWith("/") ? "/" : "") + path;
    }
    return url;
  }


  /**
   * Get the the location of the trust store.
   * @param conf
   * @return
   */
  static String getTrustStoreLocation(final Configuration conf) {
    validateConf(conf);
    return CommonUtils.getTruststoreLocation(conf, CONFIG_CAB_TRUST_STORE_LOCATION);
  }

  static String getTrustStorePass(final Configuration conf) {
    validateConf(conf);
    return CommonUtils.getTruststorePass(conf, CONFIG_CAB_TRUST_STORE_PASS);
  }

  /**
   * Get a configuration secret from the conf and then the
   * environment.
   * @param conf configuration file.
   * @param name option name
   * @param envVar environment variable name
   * @return the value
   */
  static String getConfigSecret(final Configuration conf,
                                final String        name,
                                final String        envVar) {
    validateConf(conf);
    String value = getAlias(conf, name);

    // Finally, check the environment variable, if one was specified
    if (StringUtils.isEmpty(value) && StringUtils.isNotEmpty(envVar)) {
      value = System.getenv(envVar);
    }
    return value;
  }

  /**
   * Get a configuration secret from the conf and then the
   * environment. If the value is empty or null, an exception
   * is raised.
   * @param conf configuration file.
   * @param name option name
   * @param envVar environment variable name
   * @param errorText text to use in the exception.
   * @return the value
   * @throws IllegalStateException if the secret is missing
   */
  static String getRequiredConfigSecret(final Configuration conf,
                                        final String        name,
                                        final String        envVar,
                                        final String        errorText) {
    validateConf(conf);
    String value =  getConfigSecret(conf, name, envVar);
    if (StringUtils.isEmpty(value)) {
      LOG.error(errorText);
      throw new IllegalStateException(errorText);
    }
    return value;
  }

  private static String getAlias(final Configuration conf, final String alias) {
    return CommonUtils.getPassword(conf, alias);
  }

  private static void validateConf(final Configuration conf) {
    if (conf == null) {
      LOG.info("No configuration has been provided.");
      throw new IllegalStateException("No configuration has been provided.");
    }
  }

}

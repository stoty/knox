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

import org.apache.knox.gateway.cloud.idbroker.common.Preconditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;

import java.io.IOException;
import java.lang.reflect.Constructor;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.*;

final class CABUtils {

  private static final Logger LOG = LoggerFactory.getLogger(CABUtils.class);

  private CABUtils() {
  }

  static CloudAccessBrokerClient newClient(Configuration conf) {
    CloudAccessBrokerClient client = null;

    String clientImpl = conf.get(CONFIG_CLIENT_IMPL);
    if (clientImpl != null) {
      try {
        Class clazz = Class.forName(clientImpl, false, Thread.currentThread().getContextClassLoader());
        Constructor ctor = clazz.getConstructor(Configuration.class);
        client = (CloudAccessBrokerClient) ctor.newInstance(conf);
      } catch (Exception e) {
        LOG.error("Failed to instantiate the configured CloudAccessBrokerClient implementation {} : {}",
                  clientImpl,
                  e.getMessage());
      }
    }

    if (client == null) {
      LOG.debug("Using the default CloudAccessBrokerClient");
      client = new GCPCABClient(conf);
    }

    return client;
  }

  /**
   * Get the URL of the cab
   * @param conf configuration to scan
   * @return the address, with any trailing / stripped
   * @throws IllegalArgumentException if there is none
   */
  static String getCloudAccessBrokerAddress(final Configuration conf)
      throws IllegalArgumentException{
    String address = conf.getTrimmed(CONFIG_CAB_ADDRESS, "");
    if (address.endsWith("/")) {
      address = address.substring(0, address.length() - 1);
    }
    Preconditions.checkArgument(!address.isEmpty(), "No URL provided in %s", CONFIG_CAB_ADDRESS);
    return address;
  }

  /**
   * Get URL to the gcp cab service
   * @param conf configuration to read.
   * @return the full URL to the service
   * @throws IllegalArgumentException bad configuration.
   */
  static String getCloudAccessBrokerURL(final Configuration conf) {
    return getBrokerURL(conf, CONFIG_CAB_PATH, DEFAULT_CONFIG_CAB_PATH);
  }

  /**
   * Get URL to the dt service
   * @param conf configuration to read.
   * @return the full URL to the service
   * @throws IllegalArgumentException bad configuration.
   */
  static String getDelegationTokenProviderURL(final Configuration conf) {
    return getBrokerURL(conf, CONFIG_CAB_DT_PATH, DEFAULT_CONFIG_CAB_DT_PATH);
  }

  /**
   * Get the URL to a broker component.
   * @param conf configuration to read.
   * @param key key to the specific path
   * @param defVal default value
   * @return the full URL to the service
   * @throws IllegalArgumentException bad configuration.
   */
  static String getBrokerURL(final Configuration conf, final String key, final String defVal) {
    String v = conf.getTrimmed(key, defVal);
    Preconditions.checkArgument(!v.isEmpty(), "No path in %s", key);
    return constructURL(getCloudAccessBrokerAddress(conf), v);
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
    String result =  conf.getTrimmed(CONFIG_CAB_TRUST_STORE_LOCATION);
    if (StringUtils.isEmpty(result)) {
      result = System.getenv(CONFIG_CAB_TRUST_STORE_LOCATION_ENV_VAR);
    }
    return result;
  }

  static String getTrustStorePass(final Configuration conf) {
    String result = null;

    validateConf(conf);

    // First, check the credential store
    try {
      char[] secret = conf.getPassword(CONFIG_CAB_TRUST_STORE_PASS);
      if (secret != null && secret.length > 0) {
        result = new String(secret);
      }
    } catch (IOException e) {
      //
    }

    if (StringUtils.isEmpty(result)) {
      // Check the environment variable
      result = System.getenv(CONFIG_CAB_TRUST_STORE_PASS_ENV_VAR);
    }

    return result;
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
    String result = null;
    try {
      char[] aliasValue = conf.getPassword(alias);
      if (aliasValue != null && aliasValue.length > 0) {
        result = new String(aliasValue);
      }
    } catch (IOException e) {
      LOG.info("Error accessing credential alias {}", alias);
      LOG.error("Error accessing credential alias {}", alias, e);
    }
    return result;
  }

  private static void validateConf(final Configuration conf) {
    if (conf == null) {
      LOG.info("No configuration has been provided.");
      throw new IllegalStateException("No configuration has been provided.");
    }
  }

}

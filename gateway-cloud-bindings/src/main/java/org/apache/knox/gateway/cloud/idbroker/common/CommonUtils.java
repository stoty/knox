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

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class CommonUtils {
  private static final Logger LOG = LoggerFactory.getLogger(CommonUtils.class);

  /**
   * Determine whether to use the server certificates included with delegation tokens or not.
   */
  public static boolean useCABCertFromDelegationToken(Configuration conf, String prefix) {
    return conf.getBoolean(prefix + CommonConstants.USE_CERT_FROM_DT_SUFFIX, false);
  }


  /**
   * Get the configured client trust store location associated with the specified property name.
   * If the property is not defined in the Configuration, then try to get it from the
   * hadoop.client.ssl.config property, if defined.
   *
   * @param conf A Configuration instance
   * @param propertyName The name of the trust store location property name
   *
   * @return The configured trust store location, or null.
   */
  public static String getTruststoreLocation(final Configuration conf, final String propertyName) {
    return getTruststoreLocation(conf, propertyName, null);
  }


  /**
   * Get the configured client trust store location associated with the specified property name.
   * If the property is not defined in the Configuration, then try to get it from the
   * hadoop.client.ssl.config property, if defined. If all else fails, return the specified default value.
   *
   * @param conf A Configuration instance
   * @param propertyName The name of the trust store location property name
   * @param defaultValue The default value
   *
   * @return The configured trust store location, or null.
   */
  public static String getTruststoreLocation(final Configuration conf,
                                             final String propertyName,
                                             final String defaultValue) {
    String result = conf.getTrimmed(propertyName);
    if (StringUtils.isBlank(result)) {
      ensureSSLClientConfigLoaded(conf);
      result = conf.getTrimmed(CommonConstants.SSL_TRUSTSTORE_LOCATION);
      if (StringUtils.isBlank(result)) {
        result = defaultValue;
      }
    }
    return result;
  }


  /**
   * Get the configured trust store password associated with the specified property/alias.
   * If the property/alias is not defined in the Configuration, then try to get it from the
   * hadoop.client.ssl.config property, if defined.
   *
   * @param conf A Configuration instance
   * @param propertyName The name of the trust store password property/alias
   *
   * @return The configured trust store password, or null.
   */
  public static String getTruststorePass(final Configuration conf, final String propertyName) {
    return getTruststorePass(conf, propertyName, null);
  }


  /**
   * Get the configured trust store password associated with the specified key.
   * If the key is not defined in the Configuration, then try to get it from the hadoop.client.ssl.config property,
   * if defined. If all else fails, return the specified default value.
   *
   * @param conf A Configuration instance
   * @param propertyName The name of the trust store password property/alias
   * @param defaultValue The default value
   *
   * @return The configured trust store password, or null.
   */
  public static String getTruststorePass(final Configuration conf,
                                         final String propertyName,
                                         final String defaultValue) {
    String result = getPassword(conf, propertyName);
    if (StringUtils.isBlank(result)) {
      ensureSSLClientConfigLoaded(conf);
      result = getPassword(conf, CommonConstants.SSL_TRUSTSTORE_PASS);
      if (StringUtils.isBlank(result)) {
        result = defaultValue;
      }
    }
    return result;
  }


  /**
   * Get the value of the specified secret property/alias name as a String.
   *
   * @param conf The Configuration from which to get the value.
   * @param key  The name of the property or alias.
   *
   * @return The secret value, or null.
   */
  public static String getPassword(final Configuration conf, final String key) {
    String result = null;
    try {
      char[] secret = conf.getPassword(key);
      if (secret != null && secret.length > 0) {
        result = new String(secret);
      }
    } catch (IOException e) {
      //
    }
    return result;
  }


  /**
   * If the hadoop.client.ssl.config property is defined in the specified Configuration, then make sure that the value
   * has been added as a resource so its properties can be queried from the Configuration.
   *
   * @param conf A Configuration instance
   */
  public static void ensureSSLClientConfigLoaded(final Configuration conf) {
    // Check for the common SSL client configuration reference
    String sslClientConfigLocation = conf.getTrimmed(CommonConstants.SSL_CLIENT_CONF);
    if (!StringUtils.isBlank(sslClientConfigLocation)) {
      conf.addResource(sslClientConfigLocation);
    }
  }

  /**
   * Look up a token from the credentials, verify it is of the correct
   * kind.
   *
   * @param credentials credentials to look up.
   * @param service     service name
   * @return the token or null if no suitable token was found
   * @throws IOException wrong token kind found
   */
  public static <T extends DelegationTokenIdentifier> Token<T> lookupToken(
          Credentials credentials, Text service, Text expectedKind) throws IOException
  {
    if (expectedKind == null) {
      throw new IllegalArgumentException("expectedKind is null");
    }
    LOG.debug("Looking for token for service {} in credentials", service);
    Token<?> token = credentials.getToken(service);
    if (token != null) {
      Text actualKind = token.getKind();
      LOG.debug("Found token of kind {}", actualKind);
      if (expectedKind.equals(actualKind)) {
        return (Token<T>) token;
      } else {
        throw new IOException(
                "Token mismatch: expected token"
                        + " for " + service
                        + " of type " + expectedKind
                        + " but got a token of type " + actualKind);
      }
    }
    LOG.debug("No token for {} found", service);
    return null;
  }
}

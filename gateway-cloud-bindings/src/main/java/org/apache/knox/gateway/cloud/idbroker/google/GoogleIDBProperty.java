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

import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBConstants.FS_TYPE;

import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.IDBProperty;

public enum GoogleIDBProperty implements IDBProperty {

  /**
   * {@code fs.gs.ext.cab.address}
   *
   * @see #PROPERTY_SUFFIX_GATEWAY
   */
  IDBROKER_GATEWAY(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_GATEWAY, IDBConstants.IDBROKER_GATEWAY_DEFAULT),

  /**
   * {@code fs.gs.ext.cab.dt.path}
   *
   * @see #PROPERTY_SUFFIX_DT_PATH
   */
  IDBROKER_DT_PATH(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_DT_PATH, IDBConstants.IDBROKER_DT_PATH_DEFAULT),

  /**
   * {@code fs.gs.ext.cab.dt.expiration.threshold}
   *
   * @see #PROPERTY_SUFFIX_DT_EXPIRATION_OFFSET
   */
  IDBROKER_DT_EXPIRATION_OFFSET(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_DT_EXPIRATION_OFFSET, IDBConstants.IDBROKER_DT_EXPIRATION_OFFSET_SECONDS_DEFAULT),

  /**
   * {@code fs.gs.ext.cab.path}
   *
   * @see #PROPERTY_SUFFIX_PATH
   */
  IDBROKER_PATH(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_PATH, "gcp-cab"),

  /**
   * {@code fs.gs.ext.cab.username}
   *
   * @see #PROPERTY_SUFFIX_USERNAME
   */
  IDBROKER_USERNAME(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_USERNAME, null),

  /**
   * {@code fs.gs.ext.cab.password}
   *
   * @see #PROPERTY_SUFFIX_PASSWORD
   */
  IDBROKER_PASSWORD(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_PASSWORD, null),

  /**
   * {@code fs.gs.ext.cab.truststore.location}
   *
   * @see #PROPERTY_SUFFIX_TRUSTSTORE_LOCATION
   */
  IDBROKER_TRUSTSTORE_LOCATION(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_TRUSTSTORE_LOCATION,
                               IDBConstants.DEFAULT_CERTIFICATE_PATH),

  /**
   * {@code fs.gs.ext.cab.truststore.password}
   *
   * @see #PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD
   */
  IDBROKER_TRUSTSTORE_PASSWORD(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD, null),

  /**
   * {@code fs.gs.ext.cab.truststore.pass}
   *
   * @see #PROPERTY_SUFFIX_TRUSTSTORE_PASS
   */
  IDBROKER_TRUSTSTORE_PASS(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_TRUSTSTORE_PASS, null),

  /**
   * {@code fs.gs.ext.cab.required.group}
   *
   * @see #PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD
   */
  IDBROKER_SPECIFIC_GROUP_METHOD(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD, null),

  /**
   * {@code fs.gs.ext.cab.required.role}
   *
   * @see #PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD
   */
  IDBROKER_SPECIFIC_ROLE_METHOD(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD, null),

  /**
   * {@code fs.gs.ext.cab.employ.group.role}
   *
   * @see #PROPERTY_SUFFIX_ONLY_GROUPS_METHOD
   */
  IDBROKER_ONLY_GROUPS_METHOD(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_ONLY_GROUPS_METHOD, null),

  /**
   * {@code fs.gs.ext.cab.employ.user.role}
   *
   * @see #PROPERTY_SUFFIX_ONLY_USER_METHOD
   */
  IDBROKER_ONLY_USER_METHOD(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_ONLY_USER_METHOD, null),

  /**
   * {@code fs.gs.ext.idbroker.credentials.type}
   *
   * @see #PROPERTY_SUFFIX_CREDENTIALS_TYPE
   */
  IDBROKER_CREDENTIALS_TYPE(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_CREDENTIALS_TYPE,
                            IDBConstants.IDBROKER_CREDENTIALS_KERBEROS),

  /**
   * {@code fs.gs.ext.cab.init.credentials}
   *
   * @see #PROPERTY_SUFFIX_INIT_CAB_CREDENTIALS
   */
  IDBROKER_INIT_CAB_CREDENTIALS(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_INIT_CAB_CREDENTIALS, "true"),

  /**
   * {@code fs.gs.ext.cab.use.dt.cert}
   *
   * @see #PROPERTY_SUFFIX_USE_DT_CERT
   */
  IDBROKER_USE_DT_CERT(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_USE_DT_CERT, "false"),

  /**
   * {@code fs.gs.ext.cab.token.monitor.enabled}
   *
   * @see #PROPERTY_SUFFIX_ENABLE_TOKEN_MONITOR
   */
  IDBROKER_ENABLE_TOKEN_MONITOR(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_ENABLE_TOKEN_MONITOR, "true"),

  /**
   * {@code fs.gs.ext.cab.prefer.knox.token.over.kerberos}
   *
   * @see #PROPERTY_SUFFIX_PREFER_KNOX_TOKEN_OVER_KERBEROS
   */
  IDBROKER_PREFER_KNOX_TOKEN_OVER_KERBEROS(PROPERTY_PREFIX + "." + FS_TYPE + PROPERTY_SUFFIX_PREFER_KNOX_TOKEN_OVER_KERBEROS, "true");

  private final String propertyName;
  private final String defaultValue;

  GoogleIDBProperty(String name, String value) {
    propertyName = name;
    defaultValue = value;
  }

  @Override
  public String getPropertyName() {
    return propertyName;
  }

  @Override
  public String getDefaultValue() {
    return defaultValue;
  }

}

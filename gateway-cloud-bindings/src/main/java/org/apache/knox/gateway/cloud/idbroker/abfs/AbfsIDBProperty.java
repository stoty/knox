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

package org.apache.knox.gateway.cloud.idbroker.abfs;

import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.IDBProperty;

public enum AbfsIDBProperty implements IDBProperty {

  /**
   * {@code fs.azure.ext.cab.address}
   *
   * @see #PROPERTY_SUFFIX_GATEWAY
   */
  IDBROKER_GATEWAY(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_GATEWAY, IDBConstants.IDBROKER_GATEWAY_DEFAULT),

  /**
   * {@code fs.azure.ext.cab.username}
   *
   * @see #PROPERTY_SUFFIX_USERNAME
   */
  IDBROKER_USERNAME(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_USERNAME, null),

  /**
   * {@code fs.azure.ext.cab.password}
   *
   * @see #PROPERTY_SUFFIX_PASSWORD
   */
  IDBROKER_PASSWORD(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_PASSWORD, null),

  /**
   * {@code fs.azure.ext.cab.truststore.location}
   *
   * @see #PROPERTY_SUFFIX_TRUSTSTORE_LOCATION
   */
  IDBROKER_TRUSTSTORE_LOCATION(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_TRUSTSTORE_LOCATION, IDBConstants.DEFAULT_CERTIFICATE_PATH),

  /**
   * {@code fs.azure.ext.cab.truststore.password}
   *
   * @see #PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD
   */
  IDBROKER_TRUSTSTORE_PASSWORD(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD, null),

  /**
   * {@code fs.azure.ext.cab.truststore.pass}
   *
   * @see #PROPERTY_SUFFIX_TRUSTSTORE_PASS
   */
  IDBROKER_TRUSTSTORE_PASS(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_TRUSTSTORE_PASS, null),

  /**
   * {@code fs.azure.ext.cab.required.group}
   *
   * @see #PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD
   */
  IDBROKER_SPECIFIC_GROUP_METHOD(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD, null),

  /**
   * {@code fs.azure.ext.cab.required.role}
   *
   * @see #PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD
   */
  IDBROKER_SPECIFIC_ROLE_METHOD(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD, null),

  /**
   * {@code fs.azure.ext.cab.employ.group.role}
   *
   * @see #PROPERTY_SUFFIX_ONLY_GROUPS_METHOD
   */
  IDBROKER_ONLY_GROUPS_METHOD(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_ONLY_GROUPS_METHOD, null),

  /**
   * {@code fs.azure.ext.cab.employ.user.role}
   *
   * @see #PROPERTY_SUFFIX_ONLY_USER_METHOD
   */
  IDBROKER_ONLY_USER_METHOD(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_ONLY_USER_METHOD, null),

  /**
   * {@code fs.azure.ext.cab.path}
   *
   * @see #PROPERTY_SUFFIX_PATH
   */
  IDBROKER_PATH(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_PATH, "azure-cab"),

  /**
   * {@code fs.azure.ext.cab.dt.path}
   *
   * @see #PROPERTY_SUFFIX_DT_PATH
   */
  IDBROKER_DT_PATH(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_DT_PATH, IDBConstants.IDBROKER_DT_PATH_DEFAULT),

  /**
   * {@code fs.azure.ext.idbroker.credentials.type}
   *
   * @see #PROPERTY_SUFFIX_CREDENTIALS_TYPE
   */
  IDBROKER_CREDENTIALS_TYPE(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_CREDENTIALS_TYPE, IDBConstants.IDBROKER_CREDENTIALS_KERBEROS),

  /**
   * {@code fs.azure.ext.cab.init.credentials}
   *
   * @see #PROPERTY_SUFFIX_INIT_CAB_CREDENTIALS
   */
  IDBROKER_INIT_CAB_CREDENTIALS(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_INIT_CAB_CREDENTIALS, "true"),

  /**
   * {@code fs.azure.ext.cab.use.dt.cert}
   *
   * @see #PROPERTY_SUFFIX_USE_DT_CERT
   */
  IDBROKER_USE_DT_CERT(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_USE_DT_CERT, "false"),

  /**
   * {@code fs.azure.ext.cab.test.token.path}
   *
   * @see #PROPERTY_SUFFIX_TEST_TOKEN_PATH
   */
  IDBROKER_TEST_TOKEN_PATH(PROPERTY_PREFIX + ".azure" + PROPERTY_SUFFIX_TEST_TOKEN_PATH, null);


  private final String propertyName;
  private final String defaultValue;

  AbfsIDBProperty(String propertyName, String defaultValue) {
    this.propertyName = propertyName;
    this.defaultValue = defaultValue;
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

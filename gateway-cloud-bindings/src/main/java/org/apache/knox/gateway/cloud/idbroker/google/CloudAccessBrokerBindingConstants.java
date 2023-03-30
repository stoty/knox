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

import org.apache.hadoop.io.Text;

final class CloudAccessBrokerBindingConstants {

  static final String CONFIG_PREFIX = "fs.gs.ext.cab.";

  static final String CONFIG_CAB_TRUST_STORE_LOCATION = CONFIG_PREFIX + "truststore.location";

  static final String CONFIG_CAB_TRUST_STORE_PASS = CONFIG_PREFIX + "truststore.pass";

  static final String CONFIG_CAB_TRUST_STORE_TYPE = CONFIG_PREFIX + "truststore.type";

  static final String CONFIG_CAB_ADDRESS = CONFIG_PREFIX + "address";

  static final String CONFIG_CAB_DT_PATH = CONFIG_PREFIX + "dt.path";
  static final String DEFAULT_CONFIG_CAB_DT_PATH = "dt";

  static final String CONFIG_CAB_PATH = CONFIG_PREFIX + "path";
  static final String DEFAULT_CONFIG_CAB_PATH = "gcp-cab";

  static final String CONFIG_EMPLOY_USER_ROLE = CONFIG_PREFIX + "employ.user.role";

  static final String CONFIG_CAB_EMPLOY_GROUP_ROLE = CONFIG_PREFIX + "employ.group.role";

  static final String CONFIG_CAB_REQUIRED_GROUP = CONFIG_PREFIX + "required.group";

  static final String CONFIG_CAB_REQUIRED_ROLE = CONFIG_PREFIX + "required.role";

  static final String CONFIG_DT_USERNAME = CONFIG_PREFIX + "username";

  static final String CONFIG_DT_PASS = CONFIG_PREFIX + "pass";

  /**
   * {@code fs.gs.ext.cab.test.token.path}
   */
  static final String CONFIG_TEST_TOKEN_PATH = CONFIG_PREFIX + "test.token.path";

  static final String DT_USERNAME_ENV_VAR = "CLOUD_ACCESS_BROKER_USERNAME";

  static final String DT_PASS_ENV_VAR = "CLOUD_ACCESS_BROKER_PASS";

  static final String CAB_TOKEN_NAME = "GCPDelegationToken/CloudAccessBroker";

  static final Text CAB_TOKEN_KIND = new Text(CAB_TOKEN_NAME);

  static final String IDBROKER_CREDENTIALS_TYPE = "fs.gs.idbroker.credentials.type";

  static final String HADOOP_SECURITY_AUTHENTICATION = "hadoop.security.authentication";

  static final String CONFIG_JAAS_FILE = CONFIG_PREFIX + "jaas.config";

  static final String CONFIG_KERBEROS_CONF = CONFIG_PREFIX + "kerberos.config";

  static final String CONFIG_INIT_CLOUD_CREDS = CONFIG_PREFIX + "init.credentials";

  static final String CONFIG_CLIENT_IMPL = CONFIG_PREFIX + "client.impl";

}

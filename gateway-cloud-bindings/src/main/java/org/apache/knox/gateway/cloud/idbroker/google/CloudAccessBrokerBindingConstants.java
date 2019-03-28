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

  final static String CONFIG_PREFIX = "fs.gs.ext.cab";

  final static String CONFIG_CAB_TRUST_STORE_LOCATION = CONFIG_PREFIX + ".truststore.location";

  final static String CONFIG_CAB_TRUST_STORE_LOCATION_ENV_VAR = "cab_truststore_location";

  final static String CONFIG_CAB_TRUST_STORE_PASS = CONFIG_PREFIX + ".truststore.pass";

  final static String CONFIG_CAB_TRUST_STORE_PASS_ENV_VAR = "CAB_TRUSTSTORE_PASS";

  final static String CONFIG_CAB_ADDRESS = CONFIG_PREFIX + ".address";

  final static String CONFIG_CAB_DT_PATH = CONFIG_PREFIX + ".dt.path";
  final static String DEFAULT_CONFIG_CAB_DT_PATH = "dt";

  final static String CONFIG_CAB_PATH = CONFIG_PREFIX + ".path";
  final static String DEFAULT_CONFIG_CAB_PATH = "gcp-cab";

  final static String CONFIG_EMPLOY_USER_ROLE = CONFIG_PREFIX + ".employ.user.role";

  final static String CONFIG_CAB_EMPLOY_GROUP_ROLE = CONFIG_PREFIX + ".employ.group.role";

  final static String CONFIG_CAB_REQUIRED_GROUP = CONFIG_PREFIX + ".required.group";

  final static String CONFIG_CAB_REQUIRED_ROLE = CONFIG_PREFIX + ".required.role";

  final static String CONFIG_DT_USERNAME = CONFIG_PREFIX + ".username";

  final static String CONFIG_DT_PASS = CONFIG_PREFIX + ".pass";

  final static String DT_USERNAME_ENV_VAR = "CLOUD_ACCESS_BROKER_USERNAME";

  final static String DT_PASS_ENV_VAR = "CLOUD_ACCESS_BROKER_PASS";

  final static String CAB_TOKEN_NAME = "GCPDelegationToken/CloudAccessBroker";

  final static Text CAB_TOKEN_KIND = new Text(CAB_TOKEN_NAME);

  static final String IDBROKER_CREDENTIALS_TYPE = "fs.gs.idbroker.credentials.type";

  static final String HADOOP_SECURITY_AUTHENTICATION = "hadoop.security.authentication";

  static final String CONFIG_JAAS_FILE = CONFIG_PREFIX + ".jaas.config";

  static final String CONFIG_KERBEROS_CONF = CONFIG_PREFIX + ".kerberos.config";

  static final String CONFIG_INIT_CLOUD_CREDS = CONFIG_PREFIX + ".init.credentials";

  static final String CONFIG_CLIENT_IMPL = CONFIG_PREFIX + ".client.impl";

}

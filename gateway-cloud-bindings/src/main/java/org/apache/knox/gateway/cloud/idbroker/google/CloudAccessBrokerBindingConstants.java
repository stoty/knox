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

class CloudAccessBrokerBindingConstants {

  final static String CONFIG_CAB_TRUST_STORE_LOCATION = "fs.gs.ext.cab.truststore.location";

  final static String CONFIG_CAB_TRUST_STORE_LOCATION_ENV_VAR = "CAB_TRUSTSTORE_LOCATION";

  final static String CONFIG_CAB_TRUST_STORE_PASS = "fs.gs.ext.cab.truststore.pass";

  final static String CONFIG_CAB_TRUST_STORE_PASS_ENV_VAR = "CAB_TRUSTSTORE_PASS";

  final static String CONFIG_CAB_ADDRESS = "fs.gs.ext.cab.address";

  final static String CONFIG_CAB_DT_PATH = "fs.gs.ext.cab.dt.path";
  final static String DEFAULT_CONFIG_CAB_DT_PATH = "dt";

  final static String CONFIG_CAB_PATH = "fs.gs.ext.cab.path";
  final static String DEFAULT_CONFIG_CAB_PATH = "gcp-cab";

  final static String EMPLOY_USER_ROLE = "fs.gs.ext.cab.employ.user.role";

  final static String CONFIG_CAB_EMPLOY_GROUP_ROLE = "fs.gs.ext.cab.employ.group.role";

  final static String CONFIG_CAB_REQUIRED_GROUP = "fs.gs.ext.cab.required.group";

  final static String CONFIG_CAB_REQUIRED_ROLE = "fs.gs.ext.cab.required.role";

  final static String CONFIG_DT_USERNAME = "fs.gs.ext.cab.username";

  final static String CONFIG_DT_PASS = "fs.gs.ext.cab.pass";

  final static String DT_USERNAME_ENV_VAR = "CLOUD_ACCESS_BROKER_USERNAME";

  final static String DT_PASS_ENV_VAR = "CLOUD_ACCESS_BROKER_PASS";

  final static String CAB_TOKEN_NAME = "GCPDelegationToken/CloudAccessBroker";

  final static Text CAB_TOKEN_KIND = new Text(CAB_TOKEN_NAME);

}

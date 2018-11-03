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

public class CloudAccessBrokerBindingConstants {

  public final static String CONFIG_DT_ADDRESS = "cab.delegation.token.address";

  public final static String CONFIG_CAB_ADDRESS = "cab.address";

  public final static String CONFIG_CAB_PREFER_USER_ROLE = "cab.prefer.user.role";

  public final static String CONFIG_CAB_PREFER_GROUP_ROLE = "cab.prefer.group.role";

  public final static String CONFIG_CAB_PREFERRED_GROUP = "cab.preferred.group";

  public final static String DT_USERNAME_ENV_VAR = "CLOUD_ACCESS_BROKER_USERNAME";

  public final static String DT_PASS_ENV_VAR = "CLOUD_ACCESS_BROKER_PASS";

}

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
package org.apache.knox.gateway.topology.discovery.cm.model.ssb;

import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel.Type;

public class StreamingSQLEngineModelGenerator extends AbstractStreamingSQLBuilderModelGenerator {

  static final String SERVICE = "SSB-SSE-UI";
  static final String ROLE_TYPE = "STREAMING_SQL_ENGINE";

  static final String SERVER_PORT_CONFIG_NAME = "server.port";
  static final String SSL_ENABLED_CONFIG_NAME = "ssl_enabled";

  @Override
  public String getService() {
    return SERVICE;
  }

  @Override
  public String getServiceType() {
    return SERVICE_TYPE;
  }

  @Override
  public String getRoleType() {
    return ROLE_TYPE;
  }

  @Override
  public Type getModelType() {
    return ServiceModel.Type.UI;
  }

  @Override
  protected String getPortConfigName(boolean sslEnabled) {
    return SERVER_PORT_CONFIG_NAME;
  }

  @Override
  protected String getSslEnabledConfigName() {
    return SSL_ENABLED_CONFIG_NAME;
  }

}
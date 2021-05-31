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

import java.util.Locale;

import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel.Type;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGenerator;

import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;

public abstract class AbstractStreamingSQLBuilderModelGenerator extends AbstractServiceModelGenerator {

  static final String SERVICE_TYPE = "SQL_STREAM_BUILDER";
  static final String SERVER_PORT_CONFIG_NAME = "server.port";
  static final String SSL_ENABLED_CONFIG_NAME = "server.ssl.enabled";

  @Override
  public String getServiceType() {
    return SERVICE_TYPE;
  }

  @Override
  public Type getModelType() {
    return ServiceModel.Type.API;
  }

  @Override
  public ServiceModel generateService(ApiService service, ApiServiceConfig serviceConfig, ApiRole role, ApiConfigList roleConfig) throws ApiException {
    final String hostname = role.getHostRef().getHostname();
    final boolean sslEnabled = Boolean.parseBoolean(getRoleConfigValue(roleConfig, getSslEnabledConfigName()));
    final String port = getRoleConfigValue(roleConfig, getPortConfigName(sslEnabled));
    final String scheme = getScheme(sslEnabled);

    final ServiceModel model = createServiceModel(String.format(Locale.getDefault(), "%s://%s:%s", scheme, hostname, port));
    model.addRoleProperty(getRoleType(), getSslEnabledConfigName(), Boolean.toString(sslEnabled));
    model.addRoleProperty(getRoleType(), getPortConfigName(sslEnabled), port);

    return model;
  }

  protected String getScheme(boolean sslEnabled) {
	return sslEnabled ? "https" : "http";
  }

  protected String getPortConfigName(boolean sslEnabled) {
    return SERVER_PORT_CONFIG_NAME;
  }

  protected String getSslEnabledConfigName() {
    return SSL_ENABLED_CONFIG_NAME;
  }

}

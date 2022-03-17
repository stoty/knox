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

import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel.Type;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGenerator;

import java.util.Locale;

public abstract class AbstractStreamingSQLBuilderLBModelGenerator extends AbstractServiceModelGenerator {

  static final String SERVICE_TYPE = "SQL_STREAM_BUILDER";
  static final String SERVER_PORT_CONFIG_NAME = "ssb.sse.loadbalancer.server.port";
  static final String SECURE_SERVER_PORT_CONFIG_NAME = "ssb.sse.loadbalancer.server.secure.port";
  static final String SSL_ENABLED_CONFIG_NAME = "server.ssl.enabled";
  static final String URL_CONFIG_NAME = "loadbalancer.url";

  @Override
  public String getServiceType() {
    return SERVICE_TYPE;
  }

  @Override
  public Type getModelType() {
    return Type.API;
  }

  @Override
  public ServiceModel generateService(ApiService service, ApiServiceConfig serviceConfig, ApiRole role, ApiConfigList roleConfig) throws ApiException {
    final boolean sslEnabled = Boolean.parseBoolean(getRoleConfigValue(roleConfig, getSslEnabledConfigName()));
    final String scheme = getScheme(sslEnabled);
    final String port = getRoleConfigValue(roleConfig, getPortConfigName(sslEnabled));
    final String load_balancer_url = getRoleConfigValue(roleConfig, URL_CONFIG_NAME);

    final ServiceModel model = createServiceModel(String.format(Locale.getDefault(), "%s://%s:%s", scheme, load_balancer_url, port));
    model.addRoleProperty(getRoleType(), getSslEnabledConfigName(), Boolean.toString(sslEnabled));
    model.addRoleProperty(getRoleType(), getPortConfigName(sslEnabled), port);

    return model;
  }

  protected String getScheme(boolean sslEnabled) {
    return sslEnabled ? "https" : "http";
  }

  protected String getPortConfigName(boolean sslEnabled) {
    return sslEnabled ? SECURE_SERVER_PORT_CONFIG_NAME : SERVER_PORT_CONFIG_NAME ;
  }

  protected String getSslEnabledConfigName() {
    return SSL_ENABLED_CONFIG_NAME;
  }

}

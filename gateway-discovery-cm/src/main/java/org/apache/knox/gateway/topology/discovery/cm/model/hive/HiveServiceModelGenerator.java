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
package org.apache.knox.gateway.topology.discovery.cm.model.hive;

import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGenerator;

import java.util.Locale;

public class HiveServiceModelGenerator extends AbstractServiceModelGenerator {

  public static final String SERVICE      = "HIVE";
  public static final String SERVICE_TYPE = "HIVE";
  public static final String ROLE_TYPE    = "HIVESERVER2";

  static final String TRANSPORT_MODE_HTTP = "http";

  static final String SAFETY_VALVE   = "hive_hs2_config_safety_valve";
  static final String SSL_ENABLED    = "hive.server2.use.SSL";
  static final String TRANSPORT_MODE = "hive.server2.transport.mode";
  static final String HTTP_PORT      = "hive.server2.thrift.http.port";
  static final String HTTP_PATH      = "hive.server2.thrift.http.path";

  static final String DEFAULT_HTTP_PATH = "cliservice";

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
  public ServiceModel.Type getModelType() {
    return ServiceModel.Type.API;
  }

  @Override
  public boolean handles(ApiService service, ApiServiceConfig serviceConfig, ApiRole role, ApiConfigList roleConfig) {
    return super.handles(service, serviceConfig, role, roleConfig) && checkHiveServer2HTTPMode(roleConfig);
  }

  @Override
  public ServiceModel generateService(ApiService       service,
                                      ApiServiceConfig serviceConfig,
                                      ApiRole          role,
                                      ApiConfigList    roleConfig) throws ApiException {
    String hostname = role.getHostRef().getHostname();
    boolean sslEnabled = Boolean.parseBoolean(getRoleConfigValue(roleConfig, SSL_ENABLED));
    String scheme = sslEnabled ? "https" : "http";

    String port     = getHttpPort(roleConfig);
    String httpPath = getHttpPath(roleConfig);
    if (httpPath == null) {
      httpPath = DEFAULT_HTTP_PATH;
    }

    ServiceModel model =
        createServiceModel(String.format(Locale.getDefault(), "%s://%s:%s/%s", scheme, hostname, port, httpPath));
    model.addRoleProperty(getRoleType(), SSL_ENABLED, getRoleConfigValue(roleConfig, SSL_ENABLED));
    model.addRoleProperty(getRoleType(), SAFETY_VALVE, getRoleConfigValue(roleConfig, SAFETY_VALVE));

    return model;
  }

  private String getHS2SafetyValveValue(final ApiConfigList roleConfig, final String name) {
    String value = null;
    String hs2SafetyValve = getRoleConfigValue(roleConfig, SAFETY_VALVE);
    if (hs2SafetyValve != null && !hs2SafetyValve.isEmpty()) {
      value = getSafetyValveValue(hs2SafetyValve, name);
    }
    return value;
  }

  protected String getHttpPort(ApiConfigList roleConfig) {
    return getHS2SafetyValveValue(roleConfig, HTTP_PORT);
  }

  protected String getHttpPath(ApiConfigList roleConfig) {
    return getHS2SafetyValveValue(roleConfig, HTTP_PATH);
  }

  protected boolean checkHiveServer2HTTPMode(ApiConfigList roleConfig) {
    return TRANSPORT_MODE_HTTP.equals(getHS2SafetyValveValue(roleConfig, TRANSPORT_MODE));
  }

}

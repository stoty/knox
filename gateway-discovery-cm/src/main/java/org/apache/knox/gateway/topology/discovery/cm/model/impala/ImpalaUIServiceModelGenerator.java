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
package org.apache.knox.gateway.topology.discovery.cm.model.impala;

import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModelGeneratorHandleResponse;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGenerator;

import java.util.Locale;

public class ImpalaUIServiceModelGenerator extends AbstractServiceModelGenerator {

  public static final String SERVICE      = "IMPALAUI";
  public static final String SERVICE_TYPE = "IMPALA";
  public static final String ROLE_TYPE    = "IMPALAD";

  static final String ENABLE_WEBSERVER = "impalad_enable_webserver";
  static final String SSL_ENABLED      = "client_services_ssl_enabled";
  static final String WEBSERVER_PORT   = "impalad_webserver_port";

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
    return ServiceModel.Type.UI;
  }

  @Override
  public ServiceModelGeneratorHandleResponse handles(ApiService service, ApiServiceConfig serviceConfig, ApiRole role, ApiConfigList roleConfig) {
    final ServiceModelGeneratorHandleResponse response = super.handles(service, serviceConfig, role, roleConfig);
    if (response.handled()) {
      final String impalaWebserverEnabled = getRoleConfigValue(roleConfig, ENABLE_WEBSERVER);
      if (impalaWebserverEnabled == null) {
        response.addConfigurationIssue("Missing configuration: " + ENABLE_WEBSERVER);
      } else if (!Boolean.parseBoolean(impalaWebserverEnabled)) {
        response.addConfigurationIssue("Invalid configuration: " + ENABLE_WEBSERVER + ". Expected=true; Found=" + impalaWebserverEnabled);
      }
    }
    return response;
  }

  @Override
  public ServiceModel generateService(ApiService       service,
                                      ApiServiceConfig serviceConfig,
                                      ApiRole          role,
                                      ApiConfigList    roleConfig) throws ApiException {
    String hostname = role.getHostRef().getHostname();

    String sslEnabled = getServiceConfigValue(serviceConfig, SSL_ENABLED);
    String scheme = Boolean.parseBoolean(sslEnabled) ? "https" : "http";

    String port = getRoleConfigValue(roleConfig, WEBSERVER_PORT);

    ServiceModel model = createServiceModel(String.format(Locale.getDefault(), "%s://%s:%s/", scheme, hostname, port));
    model.addServiceProperty(SSL_ENABLED, sslEnabled);
    model.addRoleProperty(getRoleType(), WEBSERVER_PORT, port);
    model.addRoleProperty(getRoleType(), ENABLE_WEBSERVER, getRoleConfigValue(roleConfig, ENABLE_WEBSERVER));

    return model;
  }
}

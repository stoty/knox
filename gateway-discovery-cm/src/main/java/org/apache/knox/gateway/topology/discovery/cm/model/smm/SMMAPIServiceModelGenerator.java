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
package org.apache.knox.gateway.topology.discovery.cm.model.smm;

import com.cloudera.api.swagger.client.ApiException;
import com.cloudera.api.swagger.model.ApiConfigList;
import com.cloudera.api.swagger.model.ApiRole;
import com.cloudera.api.swagger.model.ApiService;
import com.cloudera.api.swagger.model.ApiServiceConfig;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModel;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGenerator;

import java.util.Locale;

public class SMMAPIServiceModelGenerator extends AbstractServiceModelGenerator {

  public static final String SERVICE = "SMM-API";
  public static final String SERVICE_TYPE = "STREAMS_MESSAGING_MANAGER";
  public static final String ROLE_TYPE = "STREAMS_MESSAGING_MANAGER_SERVER";

  private static final String SSL_ENABLED = "ssl_enabled";
  private static final String SMM_PORT = "streams.messaging.manager.port";
  private static final String SMM_SSL_PORT = "streams.messaging.manager.ssl.port";

  /**
   * @return The name of the Knox service for which the implementation will
   * generate a model.
   */
  @Override
  public String getService() {
    return SERVICE;
  }

  /**
   * @return The Cloudera Manager configuration service type.
   */
  @Override
  public String getServiceType() {
    return SERVICE_TYPE;
  }

  @Override
  public ServiceModel.Type getModelType() {
    return ServiceModel.Type.API;
  }

  /**
   * @return The Cloudera Manager configuration role type.
   */
  @Override
  public String getRoleType() {
    return ROLE_TYPE;
  }

  @Override
  public ServiceModel generateService(ApiService service,
                                 ApiServiceConfig serviceConfig, ApiRole role, ApiConfigList roleConfig, ApiServiceConfig coreSettingsConfig)
      throws ApiException {
    final String hostname = role.getHostRef().getHostname();
    final String sslEnabled = getRoleConfigValue(roleConfig, SSL_ENABLED);
    final String scheme = Boolean.parseBoolean(sslEnabled) ? "https" : "http";
    final String securePort = getServiceConfigValue(serviceConfig, SMM_SSL_PORT);
    final String insecurePort = getServiceConfigValue(serviceConfig, SMM_PORT);
    final String port = Boolean.parseBoolean(sslEnabled) ? securePort : insecurePort;
    final ServiceModel serviceModel = new ServiceModel(getModelType(),
        getService(),
        getServiceType(),
        getRoleType(),
        String.format(Locale.getDefault(), "%s://%s:%s", scheme, hostname, port));

    serviceModel.addServiceProperty(SMM_SSL_PORT, securePort);
    serviceModel.addServiceProperty(SMM_PORT, insecurePort);
    serviceModel.addRoleProperty(getRoleType(), SSL_ENABLED, sslEnabled);

    return serviceModel;
  }
}

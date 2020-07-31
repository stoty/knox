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
package org.apache.knox.gateway.services.factory;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.services.GatewayServices;
import org.apache.knox.gateway.services.Service;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.services.ServiceType;
import org.apache.knox.gateway.services.topology.impl.DefaultClusterConfigurationMonitorService;

public class ClusterConfigurationMonitorServiceFactory extends AbstractServiceFactory {

  @Override
  protected Service createService(GatewayServices gatewayServices, ServiceType serviceType, GatewayConfig gatewayConfig, Map<String, String> options, String implementation)
      throws ServiceLifecycleException {
    Service service = null;
    if (shouldCreateService(implementation)) {
      service = new DefaultClusterConfigurationMonitorService();
      ((DefaultClusterConfigurationMonitorService) service).setAliasService(getAliasService(gatewayServices));
      ((DefaultClusterConfigurationMonitorService) service).setKeystoreService(getKeystoreService(gatewayServices));
    }
    return service;
  }

  @Override
  protected ServiceType getServiceType() {
    return ServiceType.CLUSTER_CONFIGURATION_MONITOR_SERVICE;
  }

  @Override
  protected Collection<String> getKnownImplementations() {
    return Collections.singleton(DefaultClusterConfigurationMonitorService.class.getName());
  }
}

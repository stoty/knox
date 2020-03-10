/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.topology.discovery.ambari;

import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.KeystoreService;
import org.apache.knox.gateway.topology.discovery.ClusterConfigurationMonitor;
import org.apache.knox.gateway.topology.discovery.ClusterConfigurationMonitorProvider;

public class AmbariClusterConfigurationMonitorProvider implements
    ClusterConfigurationMonitorProvider {

    @Override
    public String getType() {
        return AmbariConfigurationMonitor.getType();
    }

    @Override
    public ClusterConfigurationMonitor newInstance(GatewayConfig config, AliasService aliasService,
                                                   KeystoreService keystoreService) {
        return new AmbariConfigurationMonitor(config, aliasService, keystoreService);
    }
}

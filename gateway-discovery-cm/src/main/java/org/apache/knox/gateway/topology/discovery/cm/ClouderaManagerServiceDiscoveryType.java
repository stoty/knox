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
package org.apache.knox.gateway.topology.discovery.cm;

import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.topology.discovery.ServiceDiscovery;
import org.apache.knox.gateway.topology.discovery.ServiceDiscoveryType;

/**
 * ClouderaManager-based service discovery implementation type.
 */
public class ClouderaManagerServiceDiscoveryType implements ServiceDiscoveryType {

  @Override
  public String getType() {
    return ClouderaManagerServiceDiscovery.TYPE;
  }

  @Override
  public ServiceDiscovery newInstance(GatewayConfig gatewayConfig) {
    return new ClouderaManagerServiceDiscovery(gatewayConfig);
  }

}

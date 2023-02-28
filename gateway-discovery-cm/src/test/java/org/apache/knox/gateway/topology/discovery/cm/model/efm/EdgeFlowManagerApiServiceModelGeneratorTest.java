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

package org.apache.knox.gateway.topology.discovery.cm.model.efm;

import static org.apache.knox.gateway.topology.discovery.cm.model.efm.AbstractEdgeFlowManagerServiceModelGenerator.ROLE_TYPE;
import static org.apache.knox.gateway.topology.discovery.cm.model.efm.AbstractEdgeFlowManagerServiceModelGenerator.SERVICE_TYPE;
import static org.apache.knox.gateway.topology.discovery.cm.model.efm.AbstractEdgeFlowManagerServiceModelGenerator.SSL_ENABLED;
import static org.apache.knox.gateway.topology.discovery.cm.model.efm.EdgeFlowManagerApiServiceModelGenerator.EFM_C2_PORT;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.knox.gateway.topology.discovery.cm.ServiceModelGenerator;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGeneratorTest;
import org.junit.Test;

public class EdgeFlowManagerApiServiceModelGeneratorTest extends AbstractServiceModelGeneratorTest {

    @Test
    public void testServiceModelMetadata() {
        Map<String, String> roleConfig = new HashMap<>();
        roleConfig.put(SSL_ENABLED, "false");
        roleConfig.put(EFM_C2_PORT, "12345");

        Map<String, String> serviceConfig = Collections.emptyMap();

        validateServiceModel(createServiceModel(serviceConfig, roleConfig), serviceConfig, roleConfig);
    }

    @Override
    protected String getServiceType() {
        return SERVICE_TYPE;
    }

    @Override
    protected String getRoleType() {
        return ROLE_TYPE;
    }

    @Override
    protected ServiceModelGenerator newGenerator() {
        return new EdgeFlowManagerApiServiceModelGenerator();
    }
}

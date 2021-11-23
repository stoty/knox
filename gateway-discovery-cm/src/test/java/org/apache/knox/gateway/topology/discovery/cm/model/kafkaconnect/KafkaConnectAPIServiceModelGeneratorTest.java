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
package org.apache.knox.gateway.topology.discovery.cm.model.kafkaconnect;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.knox.gateway.topology.discovery.cm.ServiceModelGenerator;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGeneratorTest;
import org.junit.Test;

public class KafkaConnectAPIServiceModelGeneratorTest extends AbstractServiceModelGeneratorTest {

    @Override
    protected String getServiceType() {
        return KafkaConnectAPIServiceModelGenerator.CM_SERVICE_TYPE;
    }

    @Override
    protected String getRoleType() {
        return KafkaConnectAPIServiceModelGenerator.ROLE_TYPE;
    }

    @Override
    protected ServiceModelGenerator newGenerator() {
        return new KafkaConnectAPIServiceModelGenerator();
    }

    @Test
    public void testServiceModelMetadata() {
        Map<String, String> roleConfig = new HashMap<>();
        roleConfig.put(KafkaConnectAPIServiceModelGenerator.SSL_ENABLED, "false");
        roleConfig.put(KafkaConnectAPIServiceModelGenerator.HTTP_PORT, "28083");

        validateServiceModel(createServiceModel(Collections.emptyMap(), roleConfig), Collections.emptyMap(), roleConfig);
    }

    @Test
    public void testServiceModelMetadataSSL() {
        Map<String, String> roleConfig = new HashMap<>();
        roleConfig.put(KafkaConnectAPIServiceModelGenerator.SSL_ENABLED, "true");
        roleConfig.put(KafkaConnectAPIServiceModelGenerator.HTTPS_PORT, "28085");

        validateServiceModel(createServiceModel(Collections.emptyMap(), roleConfig), Collections.emptyMap(), roleConfig);
    }

}

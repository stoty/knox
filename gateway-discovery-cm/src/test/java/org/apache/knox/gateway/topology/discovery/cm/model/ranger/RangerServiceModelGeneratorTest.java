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
package org.apache.knox.gateway.topology.discovery.cm.model.ranger;

import org.apache.knox.gateway.topology.discovery.cm.ServiceModelGenerator;
import org.apache.knox.gateway.topology.discovery.cm.model.AbstractServiceModelGeneratorTest;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class RangerServiceModelGeneratorTest extends AbstractServiceModelGeneratorTest {

  @Test
  public void testServiceModelMetadata() {
    final Map<String, String> serviceConfig = new HashMap<>();
    serviceConfig.put(RangerServiceModelGenerator.HTTP_PORT, "2468");
    serviceConfig.put(RangerServiceModelGenerator.HTTPS_PORT, "1357");
    final Map<String, String> roleConfig = new HashMap<>();
    roleConfig.put(RangerServiceModelGenerator.SSL_ENABLED, "false");

    validateServiceModel(createServiceModel(serviceConfig, roleConfig), serviceConfig, roleConfig);
  }

  @Override
  protected String getServiceType() {
    return RangerServiceModelGenerator.SERVICE_TYPE;
  }

  @Override
  protected String getRoleType() {
    return RangerServiceModelGenerator.ROLE_TYPE;
  }

  @Override
  protected ServiceModelGenerator newGenerator() {
    return new RangerServiceModelGenerator();
  }

}

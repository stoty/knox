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
package org.apache.knox.gateway.service.definition;

import java.util.Comparator;

public class ServiceDefinitionPairComparator implements Comparator<ServiceDefinitionPair> {
  private static final ServiceDefinitionComparator SERVICE_DEFINITION_COMPARATOR = new ServiceDefinitionComparator();

  @Override
  public int compare(ServiceDefinitionPair serviceDefinitionPair, ServiceDefinitionPair otherServiceDefinitionPair) {
    final ServiceDefinition service = serviceDefinitionPair.getService();
    final ServiceDefinition otherService = otherServiceDefinitionPair.getService();
    if (service == null || otherService == null) {
      throw new IllegalArgumentException("One (or both) of the supplied service definitions is null");
    }
    return SERVICE_DEFINITION_COMPARATOR.compare(service, otherService);
  }
}

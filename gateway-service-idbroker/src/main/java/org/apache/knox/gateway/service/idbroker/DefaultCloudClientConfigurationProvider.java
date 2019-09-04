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
package org.apache.knox.gateway.service.idbroker;

import java.util.Properties;

public class DefaultCloudClientConfigurationProvider extends AbstractCloudClientConfigurationProvider {

  private static final String NAME = "Default";

  @Override
  public void init(Properties context) {
    for (Object key : context.keySet()) {
      setProperty((String) key, context.getProperty((String) key));
    }
  }

  @Override
  public String getName() {
    return NAME;
  }

}

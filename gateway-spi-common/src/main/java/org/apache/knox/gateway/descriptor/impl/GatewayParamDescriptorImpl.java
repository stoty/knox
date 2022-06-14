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
package org.apache.knox.gateway.descriptor.impl;

import org.apache.knox.gateway.descriptor.GatewayDescriptor;
import org.apache.knox.gateway.descriptor.GatewayParamDescriptor;

public class GatewayParamDescriptorImpl implements GatewayParamDescriptor {

  private GatewayDescriptor parent;
  private String name;
  private String value;

  GatewayParamDescriptorImpl( GatewayDescriptor parent ) {
    this.parent = parent;
  }

  @Override
  public void up( GatewayDescriptor parent ) {
    this.parent = parent;
  }

  @Override
  public GatewayDescriptor up() {
    return parent;
  }

  @Override
  public GatewayParamDescriptor name( String name ) {
    this.name = name;
    return this;
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public GatewayParamDescriptor value( String value ) {
    this.value = value;
    return this;
  }

  @Override
  public String value() {
    return value;
  }
}

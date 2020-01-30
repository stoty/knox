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
package org.apache.knox.gateway.topology.discovery;

public class DefaultServiceDiscoveryConfig implements ServiceDiscoveryConfig {
    private String address;
    private String cluster;
    private String user;
    private String pwdAlias;

    public DefaultServiceDiscoveryConfig(String address) {
        this.address = address;
    }

    public void setUser(String username) {
        this.user = username;
    }

    public void setPasswordAlias(String alias) {
        this.pwdAlias = alias;
    }

    @Override
    public String getAddress() {
        return address;
    }

    public void setCluster(String cluster) {
        this.cluster = cluster;
    }

    @Override
    public String getCluster() {
        return cluster;
    }

    @Override
    public String getUser() {
        return user;
    }

    @Override
    public String getPasswordAlias() {
        return pwdAlias;
    }

}

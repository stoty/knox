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
package org.apache.knox.gateway.shell.idbroker;

import org.apache.http.HttpRequest;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxShellException;

import java.net.SocketException;

public class AlwaysSocketExceptionCredentialsRequest extends AbstractBrokenCredentialsRequest {

  public AlwaysSocketExceptionCredentialsRequest(CloudAccessBrokerSession session) {
    super(session, HttpStatus.SC_OK);
  }

  @Override
  protected CloseableHttpResponse execute(HttpRequest request) {
    throw new KnoxShellException(new SocketException("I always encounter a SocketException"));
  }
}
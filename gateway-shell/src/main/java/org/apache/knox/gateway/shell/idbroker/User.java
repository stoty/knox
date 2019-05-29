/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership.  The ASF
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
package org.apache.knox.gateway.shell.idbroker;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;
import org.apache.knox.gateway.shell.AbstractRequest;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.KnoxSession;

import java.net.URI;
import java.util.concurrent.Callable;

/**
 * Gets credentials for the authenticated user.
 */
public class User {

  final static String USER_CREDENTIALS_API_PATH =
      Credentials.SERVICE_PATH + "/user";

  public static class Request extends AbstractCloudAccessBrokerRequest<Response> {

    Request(final CloudAccessBrokerSession session) {
      super(session);
    }

    @Override
    protected Callable<Response> callable() {
      return () -> {
        URI uri = uri(USER_CREDENTIALS_API_PATH).build();
        HttpGet request = new HttpGet(uri);
        return new Response(execute(request));
      };
    }
  }

  static class Response extends BasicResponse {
    Response(HttpResponse response) {
      super(response);
    }
  }

}

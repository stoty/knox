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
package org.apache.knox.gateway.shell.idbroker;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.Callable;

import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;

/**
 * Acquire a cloud vendor credentials for authentication
 * to access vendor REST APIs
 */
public class Get {
  public static class Request extends AbstractCloudAccessBrokerRequest<Response> {

    Request(CloudAccessBrokerSession session) {
      super(session);
    }

    @Override
    protected Callable<Response> callable() {
      return new Callable<Response>() {
        @Override
        public Response call() throws Exception {
          URI uri = uri(Credentials.SERVICE_PATH).build();
          HttpGet request = new HttpGet(uri);
          return new Response(execute(request));
        }
      };
    }
  }

  public static class Response extends BasicResponse {
    Response(HttpResponse response) throws IOException {
      super(response);
    }
  }
}

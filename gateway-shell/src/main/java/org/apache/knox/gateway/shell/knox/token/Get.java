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
package org.apache.knox.gateway.shell.knox.token;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

import org.apache.http.NameValuePair;
import org.apache.knox.gateway.shell.AbstractRequest;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.knox.gateway.shell.KnoxShellException;

/**
 * Acquire a Knox access token for token based authentication
 * to access REST APIs
 */
public class Get {
  public static class Request extends AbstractRequest<Response> {
    Request(KnoxSession session) {
      this(session, null, Collections.emptyList());
    }

    Request(KnoxSession session, String doAsUser) {
      this(session, doAsUser, Collections.emptyList());
    }

    Request(KnoxSession session, String doAsUser, List<NameValuePair> queryParameters) {
      super(session, doAsUser);
      try {
        URIBuilder uri = uri(Token.SERVICE_PATH);
        uri.addParameters(queryParameters);
        requestURI = uri.build();
      } catch (URISyntaxException e) {
        throw new KnoxShellException(e);
      }
    }

    private URI requestURI;

    private HttpGet httpGetRequest;

    public URI getRequestURI() {
      return requestURI;
    }

    public HttpGet getRequest() {
      return httpGetRequest;
    }

    @Override
    protected Callable<Response> callable() {
      return () -> {
        httpGetRequest = new HttpGet(requestURI);
        if (getHttpRequestConfig() != null) {
          httpGetRequest.setConfig(getHttpRequestConfig());
        }
        return new Response(execute(httpGetRequest));
      };
    }
  }

  public static class Response extends BasicResponse {
    Response(HttpResponse response) throws IOException {
      super(response);
    }
  }
}

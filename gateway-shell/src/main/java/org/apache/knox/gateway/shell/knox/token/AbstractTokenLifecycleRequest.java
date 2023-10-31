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
package org.apache.knox.gateway.shell.knox.token;

import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.knox.gateway.shell.AbstractRequest;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.KnoxShellException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.Callable;

public abstract class AbstractTokenLifecycleRequest extends AbstractRequest<TokenLifecycleResponse> {

  private final URI requestURI;
  private final String token;

  AbstractTokenLifecycleRequest(final KnoxSession session, final String token) {
    this(session, token, null);
  }

  AbstractTokenLifecycleRequest(final KnoxSession session, final String token, final String doAsUser) {
    super(session, doAsUser);
    this.token = token;
    try {
      URIBuilder uri = uri(Token.SERVICE_PATH, "/", getOperation());
      requestURI = uri.build();
    } catch (URISyntaxException e) {
      throw new KnoxShellException(e);
    }
  }

  protected abstract String getOperation();

  protected abstract HttpEntityEnclosingRequestBase getRequest();

  public URI getRequestURI() {
    return requestURI;
  }

  public String getToken() {
    return token;
  }

  @Override
  protected Callable<TokenLifecycleResponse> callable() {
    return () -> {
      try {
        final HttpEntityEnclosingRequestBase request = getRequest();
        if (getHttpRequestConfig() != null) {
          request.setConfig(getHttpRequestConfig());
        }
        return new TokenLifecycleResponse(execute(request));
      } catch (ErrorResponse e) {
        return new TokenLifecycleResponse(e.getResponse());
      }
    };
  }
}



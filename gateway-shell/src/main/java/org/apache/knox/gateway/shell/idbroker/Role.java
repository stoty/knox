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

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.knox.gateway.shell.AbstractRequest;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.KnoxSession;

import java.net.URI;
import java.util.concurrent.Callable;

/**
 * Gets credentials for the given role.
 */
public class Role {

  final static String ROLE_CREDENTIALS_API_PATH =
      Credentials.SERVICE_PATH + "/role";

  public static class Request extends AbstractRequest<Response> {

    private String roleid = null;

    Request(final KnoxSession session) {
      super(session);
    }

    /**
     * Get the roleid
     *
     * @param roleid
     * @return
     */
    public Request roleid(final String roleid) {
      this.roleid = roleid;
      return this;
    }

    @Override
    protected Callable<Response> callable() {

      return () -> {
        URI uri = uri(ROLE_CREDENTIALS_API_PATH).build();
        /* if we have roleid defined use it to build the path */
        if (!StringUtils.isBlank(roleid)) {
          uri = uri(ROLE_CREDENTIALS_API_PATH + "/" + roleid).build();
        }
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

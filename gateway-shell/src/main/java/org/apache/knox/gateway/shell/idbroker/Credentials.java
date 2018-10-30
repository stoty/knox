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

import org.apache.knox.gateway.shell.KnoxSession;

public class Credentials {

  static String SERVICE_PATH = "/cab/api/v1/credentials";

  /**
   * Get credentials
   * @param session
   * @return
   */
  public static Get.Request get(final KnoxSession session ) {
    return new Get.Request( session );
  }

  /**
   * Get credentials for user
   * @param session
   * @return
   */
  public static User.Request forUser(final KnoxSession session) {
    return new User.Request(session);
  }

  /**
   * Get credentials for role
   * @param session
   * @return
   */
  public static Role.Request forRole(final KnoxSession session) {
    return new Role.Request(session);
  }

  /**
   * Get crendetials for group
   * @param session
   * @return
   */
  public static Group.Request forGroup(final KnoxSession session) {
    return new Group.Request(session);
  }

}

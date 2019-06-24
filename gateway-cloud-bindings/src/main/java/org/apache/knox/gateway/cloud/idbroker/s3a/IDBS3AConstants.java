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

package org.apache.knox.gateway.cloud.idbroker.s3a;

import org.apache.hadoop.io.Text;

final class IDBS3AConstants {

  static final String FS_TYPE = "s3a";

  /**
   * Name of token: {@value}.
   */
  static final String IDB_TOKEN_NAME = "S3ADelegationToken/IDBroker";
  /**
   * Kind of token; value is {@link #IDB_TOKEN_NAME}.
   */
  static final Text IDB_TOKEN_KIND = new Text(IDB_TOKEN_NAME);

  private IDBS3AConstants() {
  }

}

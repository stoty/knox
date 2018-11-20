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

package org.apache.knox.gateway.cloud.idbroker.commands;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.shell.CommandFormat;
import org.apache.hadoop.service.launcher.LauncherExitCodes;
import org.apache.hadoop.util.ToolRunner;
import org.apache.knox.gateway.cloud.BrokerEntryPoint;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;

import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDBROKER_TOKEN;

public class FetchIDBToken extends BrokerEntryPoint {

  protected static final Logger LOG =
      LoggerFactory.getLogger(FetchIDBToken.class);

  /**
   * Execute the command, return the result or throw an exception,
   * as appropriate.
   * @param args argument varags.
   * @return return code
   * @throws Exception failure
   */
  public static int exec(String... args) throws Exception {
    return ToolRunner.run(new FetchIDBToken(), args);
  }

  /**
   * Main entry point. Calls {@code System.exit()} on all execution paths.
   * @param args argument list
   */
  public static void main(String[] args) {
    try {
      exit(exec(args), "");
    } catch (CommandFormat.UnknownOptionException e) {
      errorln(e.getMessage());
      exit(LauncherExitCodes.EXIT_USAGE, e.getMessage());
    } catch (Throwable e) {
      e.printStackTrace(System.err);
      exit(LauncherExitCodes.EXIT_FAIL, e.toString());
    }
  }

  @Override
  public int run(String[] args) throws Exception {
    IDBClient idbClient = new IDBClient(new Configuration());
    String token = fetchAdminToken(idbClient);

    heading("XML");
    println("<property>%n"
            + "  <name>" + IDBROKER_TOKEN + "</name>%n"
            + "  <value>%s</value>%n"
            + "</property>",
        token);


    // bash
    heading("Bash Environment vars");
    println("export IDBTOKEN=%s", token);

    // fish, tcsh, etc.
    heading("Fish");
    println("set -gx IDBTOKEN %s", token);

    heading("Usage");
    println("hadoop fs -D%s=$IDBTOKEN ",
        IDBROKER_TOKEN);


    return 0;
  }

  protected String fetchAdminToken(final IDBClient client) throws IOException {
    String token = client.requestKnoxDelegationToken(
        client.knoxDtSession(IDBConstants.ADMIN_USER,
            IDBConstants.ADMIN_PASSWORD)).access_token;
    return token;
  }
}

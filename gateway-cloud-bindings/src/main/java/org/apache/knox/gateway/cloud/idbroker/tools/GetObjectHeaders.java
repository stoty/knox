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
package org.apache.knox.gateway.cloud.idbroker.tools;

import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.shell.CommandFormat;
import org.apache.hadoop.util.ExitUtil;
import org.apache.hadoop.util.ToolRunner;

import static org.apache.hadoop.service.launcher.LauncherExitCodes.EXIT_NOT_ACCEPTABLE;
import static org.apache.hadoop.service.launcher.LauncherExitCodes.EXIT_NOT_FOUND;
import static org.apache.hadoop.service.launcher.LauncherExitCodes.EXIT_USAGE;

/**
 * Provides a CLI entry point to get the headers of an s3 object.
 * This relies on an S3A Filesystem with HADOOP-17414, which
 * implements the XAttr API and returns all object metadata
 * headers with the prefix "header.".
 * <pre>
 * $ bin/hadoop fs -getfattr -d s3a://bucket/file1
 * # file: s3a://bucket/file1
 * header.Content-Length="0"
 * header.Content-Type="application/octet-stream"
 * header.ETag=""bd13f4ecafd9ca52a6e8a4bb11e0fb1e""
 * header.Last-Modified="Wed Jul 19 12:43:49 BST 2023"
 * header.x-amz-server-side-encryption="aws:kms"
 * header.x-amz-version-id="HEZGxW09usNTOTKMOE6n_4sDPG52AbA8"
 * </pre>
 * This entry point invokes the operation, then strips off the "header."
 * prefix before printing or comparing any header supplied with a "-req"
 * argument. The resultant output for the same object as queried earlier
 * will be.
 * <pre>
 * $ hadoop org.apache.knox.gateway.cloud.idbroker.tools.GetObjectHeaders \
 *  -req ETag=bd13f4ecafd9ca52a6e8a4bb11e0fb1e s3a://bucket/file1
 *
 * Last-Modified: "Wed Jul 19 12:43:49 BST 2023"
 * Content-Length: "0"
 * x-amz-server-side-encryption: "aws:kms"
 * ETag: "bd13f4ecafd9ca52a6e8a4bb11e0fb1e"
 * x-amz-version-id: "HEZGxW09usNTOTKMOE6n_4sDPG52AbA8"
 * Content-Type: "application/octet-stream"
 * </pre>
 * Takes: a path.
 */
@SuppressWarnings("UseOfSystemOutOrSystemErr")
public class GetObjectHeaders extends BrokerEntryPoint {
  public static final String USAGE =
      "Usage: GetObjectHeaders [-req header=value] <file>";

  public static final String REQUIRE = "req";
  public static final String PREFIX = "header.";

  public GetObjectHeaders() {
    setCommandFormat(
        new CommandFormat(1, 1));
    getCommandFormat().addOptionWithValue(REQUIRE);
  }

  public int run(String[] args, PrintStream stream) throws Exception {
    setOut(stream);
    List<String> paths = parseArgs(args);
    if (paths.size() != 1) {
      errorln(USAGE);
      return EXIT_USAGE;
    }
    final Configuration conf = new Configuration();
    final Path source = new Path(paths.get(0));
    FileSystem fs = source.getFileSystem(conf);
    try {
      // retrieve the headers of any object at the path.
      final Map<String, byte[]> xAttrs = fs.getXAttrs(source);

      // convert to string and strip off any header. prefix.
      Map<String, String> headers = new HashMap<>(xAttrs.size());
      xAttrs.forEach((k, bytes) -> {
        String key = k;
        String v2 = new String(bytes, StandardCharsets.UTF_8);
        if (key.startsWith(PREFIX)) {
          key = key.substring(PREFIX.length());
        }
        headers.put(key, v2);
      });
      for (Map.Entry<String, String> entry : headers.entrySet()) {
        println("%s: \"%s\"", entry.getKey(), entry.getValue());
      }
      // check the header
      getOptional(REQUIRE).ifPresent(required ->
            verifyHeaderIsPresent(required, headers));

    } catch (FileNotFoundException e) {
      throw new ExitUtil.ExitException(EXIT_NOT_FOUND, source.toString(), e);
    }
    return 0;

  }

  /**
   * Verify that a header is present.
   * @param required required header
   * @param headers map of headers of object
   */
  private void verifyHeaderIsPresent(final String required,
      final Map<String, String> headers) {
    int split = required.indexOf('=');
    int len = required.length();
    if (split == 0 || split + 1 == len) {
      throw new ExitUtil.ExitException(EXIT_USAGE,
          "Failed to parse required option of " + required);
    }
    String header;
    String expected;
    header = split > 0 ? required.substring(0, split) : required;
    expected = split > 0 ? required.substring(split + 1, len) : null;
    String headerVal = headers.get(header);
    if (headerVal == null) {
      throw new ExitUtil.ExitException(EXIT_NOT_ACCEPTABLE,
          "No header " + header);
    }
    String actual = headerVal;
    // if an expected value was set: verify it.
    if (expected != null && !expected.equals(actual)) {
      throw new ExitUtil.ExitException(EXIT_NOT_ACCEPTABLE,
          "Value of header " + header
              + " must be \"" + expected + "\""
              + " but is \"" + actual + "\"");
    }
    println("Verified value of %s is %s", header, actual);
  }

  @Override
  public final int run(String[] args) throws Exception {
    return run(args, System.out);
  }

  /**
   * Execute the command, return the result or throw an exception,
   * as appropriate.
   * @param args argument varags.
   * @return return code
   * @throws Exception failure
   */
  public static int exec(String... args) throws Exception {
    return ToolRunner.run(new GetObjectHeaders(), args);
  }

  /**
   * Main entry point. Calls {@code System.exit()} on all execution paths.
   * @param args argument list
   */
  public static void main(String[] args) {
    try {
      exit(exec(args), "");
    } catch (Throwable e) {
      exitOnThrowable(e);
    }
  }
}

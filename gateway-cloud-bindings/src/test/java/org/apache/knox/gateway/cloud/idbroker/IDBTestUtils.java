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

package org.apache.knox.gateway.cloud.idbroker;

import java.io.File;
import java.io.IOException;

import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileUtil;
import org.apache.hadoop.fs.contract.ContractTestUtils;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.Statistic;
import org.apache.hadoop.io.DataInputBuffer;
import org.apache.hadoop.io.DataOutputBuffer;
import org.apache.hadoop.io.Writable;
import org.apache.hadoop.service.Service;
import org.apache.hadoop.service.ServiceOperations;
import org.apache.hadoop.service.launcher.LauncherExitCodes;
import org.apache.hadoop.util.ReflectionUtils;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_CREDENTIAL_PROVIDER_PATH;
import static org.apache.hadoop.fs.s3a.Constants.BUFFER_DIR;
import static org.apache.hadoop.fs.s3a.Constants.FS_S3A_BUCKET_PREFIX;
import static org.apache.hadoop.fs.s3a.Constants.HADOOP_TMP_DIR;
import static org.apache.hadoop.fs.s3a.commit.CommitConstants.MAGIC_COMMITTER_ENABLED;
import static org.apache.hadoop.test.LambdaTestUtils.intercept;

/**
 * Copy and paste from S3ATestUtils and other static test helper classes.
 * Because of that fact: Don't bother making "improvements" here: do it in
 * the origin classes and then copy over.
 */
public final class IDBTestUtils extends Assert {

  private static final Logger LOG = LoggerFactory.getLogger(IDBTestUtils.class);

  private IDBTestUtils() {
  }

  public static int exec(Tool tool, String... args) throws Exception {
    return ToolRunner.run(tool, args);
  }

  public static void expectSuccess(Tool tool, String... args) throws Exception {
    expectOutcome(0, tool, args);
  }

  public static void expectUsageError(Tool tool, String... args)
      throws Exception {
    expectOutcome(LauncherExitCodes.EXIT_USAGE, tool, args);
  }

  public static <E extends Throwable> E expectException(Class<E> clazz,
      final Tool tool,
      final String... args) throws Exception {
    return intercept(clazz,
        () -> exec(tool, args));
  }

  private static String robustToString(Object o) {
    if (o == null) {
      return "(null)";
    } else {
      try {
        return o.toString();
      } catch (Exception e) {
        LOG.info("Exception calling toString()", e);
        return o.getClass().toString();
      }
    }
  }


  public static void expectOutcome(int expected, Tool tool, String... args)
      throws Exception {
    assertEquals(toString(args), expected, exec(tool, args));
  }

  public static String toString(String[] args) {
    return "exec(" + StringUtils.join(args, " ") + ")";
  }

  public static void mkdirs(File dir) {
    assertTrue("Failed to create " + dir, dir.mkdirs());
  }


  public static File createTestDir() throws IOException {
    String testDir = System.getProperty("test.build.data");
    File testDirectory;
    if (testDir == null) {
      File tf = File.createTempFile("TestLocalCloudup", ".dir");
      tf.delete();
      testDir = tf.getAbsolutePath();
      testDirectory = new File(testDir);
    } else {
      testDirectory = new File(testDir);
      // test dir from sysprop; force delete
      FileUtil.fullyDelete(testDirectory);
    }
    mkdirs(testDirectory);
    return testDirectory;
  }

  /**
   * Create some test files
   * @param destDir destination; things to in under it.
   * @param fileCount total number of files
   * @return number of expected files in recursive enum
   * @throws IOException
   */
  public static int createTestFiles(File destDir, int fileCount)
      throws IOException {
    File subdir = new File(destDir, "subdir");
    int expected = 0;
    mkdirs(subdir);
    File top = new File(destDir, "top");
    FileUtils.write(top, "toplevel");
    expected++;
    for (int i = 0; i < fileCount; i++) {
      String text = String.format("file-%02d", i);
      File f = new File(subdir, text);
      FileUtils.write(f, f.toString());
    }
    expected += fileCount;

    // and write the largest file
    File largest = new File(subdir, "largest");
    FileUtils.writeByteArrayToFile(largest,
        ContractTestUtils.dataset(8192, 32, 64));
    expected++;
    return expected;
  }


  /**
   * Patch a configuration for testing.
   * This includes possibly enabling s3guard, setting up the local
   * FS temp dir and anything else needed for test runs.
   * @param conf configuration to patch
   * @return the now-patched configuration
   */
  public static Configuration prepareTestConfiguration(final Configuration conf) {
    // set hadoop temp dir to a default value
    String testUniqueForkId =
        System.getProperty("test.unique.fork.id");
    String tmpDir = conf.get(HADOOP_TMP_DIR, "target/build/test");
    if (testUniqueForkId != null) {
      // patch temp dir for the specific branch
      tmpDir = tmpDir + File.pathSeparatorChar + testUniqueForkId;
      conf.set(HADOOP_TMP_DIR, tmpDir);
    }
    conf.set(BUFFER_DIR, tmpDir);
    // add this so that even on tests where the FS is shared,
    // the FS is always "magic"
    conf.setBoolean(MAGIC_COMMITTER_ENABLED, true);
    return conf;
  }

  /**
   * Turn off FS Caching: use if a filesystem with different options from
   * the default is required.
   * @param conf configuration to patch
   */
  public static void disableFilesystemCaching(Configuration conf) {
    conf.setBoolean("fs.s3a.impl.disable.cache", true);
  }

  /**
   * Clear any Hadoop credential provider path.
   * This is needed if people's test setups switch to credential providers,
   * and the test case is altering FS login details: changes made in the
   * config will not be picked up.
   * @param conf configuration to update
   */
  public static void unsetHadoopCredentialProviders(final Configuration conf) {
    conf.unset(HADOOP_SECURITY_CREDENTIAL_PROVIDER_PATH);
  }

  /**
   * Deploy a hadoop service: init and start it.
   * @param conf configuration to use
   * @param service service to configure
   * @param <T> type of service
   * @return the started service
   */
  public static <T extends Service> T deployService(Configuration conf,
      T service) {
    service.init(conf);
    service.start();
    return service;
  }

  /**
   * Terminate a service, returning {@code null} cast at compile-time
   * to the type of the service, for ease of setting fields to null.
   * @param service service.
   * @param <T> type of the service
   * @return null, always
   */
  @SuppressWarnings("ThrowableNotThrown")
  public static <T extends Service> T terminateService(T service) {
    ServiceOperations.stopQuietly(LOG, service);
    return null;
  }

  /**
   * Remove any values from a bucket.
   * @param bucket bucket whose overrides are to be removed. Can be null/empty
   * @param conf config
   * @param options list of fs.s3a options to remove
   */
  public static void removeBucketOverrides(String bucket,
      Configuration conf, String... options) {

    if (StringUtils.isEmpty(bucket)) {
      return;
    }
    final String bucketPrefix = FS_S3A_BUCKET_PREFIX + bucket + '.';
    for (String option : options) {
      final String stripped = option.substring("fs.s3a.".length());
      String target = bucketPrefix + stripped;
      if (conf.get(target) != null) {
        LOG.debug("Removing option {}", target);
        conf.unset(target);
      }
    }
  }

  /**
   * Remove any values from a bucket and the base values too.
   * @param bucket bucket whose overrides are to be removed. Can be null/empty.
   * @param conf config
   * @param options list of fs.s3a options to remove
   */
  public static void removeBaseAndBucketOverrides(String bucket,
      Configuration conf, String... options) {
    for (String option : options) {
      conf.unset(option);
    }
    removeBucketOverrides(bucket, conf, options);
  }

  /**
   * Round trip a writable to a new instance.
   * @param source source object
   * @param conf configuration
   * @param <T> type
   * @return an unmarshalled instance of the type
   * @throws Exception on any failure.
   */
  @SuppressWarnings("unchecked")
  public static <T extends Writable> T roundTrip(T source, Configuration conf)
      throws Exception {
    DataOutputBuffer dob = new DataOutputBuffer();
    source.write(dob);

    DataInputBuffer dib = new DataInputBuffer();
    dib.reset(dob.getData(), dob.getLength());

    T after = ReflectionUtils.newInstance((Class<T>) source.getClass(), conf);
    after.readFields(dib);
    return after;
  }

  /**
   * Helper class to do diffs of metrics.
   */
  public static final class MetricDiff {

    private final S3AFileSystem fs;

    private final Statistic statistic;

    private long startingValue;

    /**
     * Constructor.
     * Invokes {@link #reset()} so it is immediately capable of measuring the
     * difference in metric values.
     *
     * @param fs the filesystem to monitor
     * @param statistic the statistic to monitor.
     */
    public MetricDiff(S3AFileSystem fs, Statistic statistic) {
      this.fs = fs;
      this.statistic = statistic;
      reset();
    }

    /**
     * Reset the starting value to the current value.
     * Diffs will be against this new value.
     */
    public void reset() {
      startingValue = currentValue();
    }

    /**
     * Get the current value of the metric.
     * @return the latest value.
     */
    public long currentValue() {
      return fs.getInstrumentation().getCounterValue(statistic);
    }

    /**
     * Get the difference between the the current value and
     * {@link #startingValue}.
     * @return the difference.
     */
    public long diff() {
      return currentValue() - startingValue;
    }

    @Override
    public String toString() {
      long c = currentValue();
      final StringBuilder sb = new StringBuilder(statistic.getSymbol());
      sb.append(" starting=").append(startingValue);
      sb.append(" current=").append(c);
      sb.append(" diff=").append(c - startingValue);
      return sb.toString();
    }

    /**
     * Assert that the value of {@link #diff()} matches that expected.
     * @param message message to print; metric name is appended
     * @param expected expected value.
     */
    public void assertDiffEquals(String message, long expected) {
      Assert.assertEquals(message + ": " + statistic.getSymbol(),
          expected, diff());
    }

    /**
     * Assert that the value of {@link #diff()} matches that expected.
     * @param expected expected value.
     */
    public void assertDiffEquals(long expected) {
      assertDiffEquals("Count of " + this, expected);
    }

    /**
     * Assert that the value of {@link #diff()} matches that of another
     * instance.
     * @param that the other metric diff instance.
     */
    public void assertDiffEquals(MetricDiff that) {
      Assert.assertEquals(this.toString() + " != " + that,
          this.diff(), that.diff());
    }

    /**
     * Comparator for assertions.
     * @param that other metric diff
     * @return true if the value is {@code ==} the other's
     */
    public boolean diffEquals(MetricDiff that) {
      return this.diff() == that.diff();
    }

    /**
     * Comparator for assertions.
     * @param that other metric diff
     * @return true if the value is {@code <} the other's
     */
    public boolean diffLessThan(MetricDiff that) {
      return this.diff() < that.diff();
    }

    /**
     * Comparator for assertions.
     * @param that other metric diff
     * @return true if the value is {@code <=} the other's
     */
    public boolean diffLessThanOrEquals(MetricDiff that) {
      return this.diff() <= that.diff();
    }

    /**
     * Get the statistic.
     * @return the statistic
     */
    public Statistic getStatistic() {
      return statistic;
    }

    /**
     * Get the starting value; that set in the last {@link #reset()}.
     * @return the starting value for diffs.
     */
    public long getStartingValue() {
      return startingValue;
    }
  }
}

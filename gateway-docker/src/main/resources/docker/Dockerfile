# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM docker-private.infra.cloudera.com/cloudera_base/ubi8/cldr-openjdk-17-runtime-cis:1.17-4-cis-31102023
MAINTAINER Apache Knox <dev@knox.apache.org>

# Make sure required packages are available
RUN microdnf upgrade && \
    microdnf -y install openssl && \
	microdnf -y install procps && \
	microdnf -y install ca-certificates && \
	microdnf -y install unzip && \
	update-ca-trust

# Create an knox user
RUN groupadd --system -g 8000 knox && adduser --system -g knox knox -d /home/knox -m

# Dependencies
ARG RELEASE_FILE
COPY ${RELEASE_FILE} /home/knox/

# Extract the Knox release tar.gz
RUN cd /home/knox && unzip /home/knox/*.zip && rm -f /home/knox/*.zip && ln -nsf /home/knox/*/ /home/knox/knox

# Make sure knox owns its files
RUN chown -R knox: /home/knox

# Add the entrypoint script
ARG ENTRYPOINT
COPY ${ENTRYPOINT} /home/knox/knox/entrypoint.sh
RUN chmod +x /home/knox/knox/entrypoint.sh

# Add the Amazon Root CA certificates
ADD --chown=knox:knox \
    http://www.awstrust.com/repository/AmazonRootCA1.cer \
    http://www.awstrust.com/repository/AmazonRootCA2.cer \
    http://www.awstrust.com/repository/AmazonRootCA3.cer \
    http://www.awstrust.com/repository/AmazonRootCA4.cer ${JAVA_HOME}/jre/lib/security/cacrts/

WORKDIR /home/knox/knox

# Expose the default port as a convenience
ARG EXPOSE_PORT
EXPOSE ${EXPOSE_PORT}

# Switch off of the root user
USER knox
ENTRYPOINT ["./entrypoint.sh"]

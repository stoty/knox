 #!/usr/bin/env bash

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

set -ex

export MAVEN_OPTS="${MAVEN_OPTS} -Xmx1g -XX:MaxPermSize=256m"

cat > mvn_settings.xml <<EOF
<settings>
<localRepository/>
<mirrors>
    <mirror>
        <id>public</id>
        <mirrorOf>*</mirrorOf>
        <url>https://nexus-private.hortonworks.com/nexus/content/groups/public</url>
    </mirror>
</mirrors>
<profiles/>
</settings>
EOF

echo "::>> cat mvn_settings.xml"

cat mvn_settings.xml

echo "Running unitttests.."

mvn -s mvn_settings.xml --update-snapshots -Dshellcheck=false -Drat.skip=true clean install -Prelease,package,idbroker -pl \!gateway-docker

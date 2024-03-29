#!/bin/sh
set -x
set -e

# Skip redundant test & checks
MVN_ARGS="clean deploy -B -Dcheckstyle.skip=true -DskipTests -Dskip.assembly=true --settings ./.travis/settings.xml"

mvn ${MVN_ARGS}
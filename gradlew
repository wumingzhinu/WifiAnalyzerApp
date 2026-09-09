#!/bin/sh

##############################################################################
## Gradle start up script for POSIX
##############################################################################

APP_HOME=$( cd "${0%/*}" > /dev/null && pwd -P ) || exit
APP_BASE_NAME=${0##*/}

MAX_FD=maximum

warn () { echo "$*" >&2 ; }
die () { echo; echo "$*"; echo; exit 1 ; }

cygwin=false
msys=false
darwin=false
nonstop=false
case "$( uname )" in
  CYGWIN* )         cygwin=true  ;;
  Darwin* )         darwin=true  ;;
  MSYS* | MINGW* )  msys=true   ;;
  NonStop* )        nonstop=true ;;
esac

CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar

if [ -n "$JAVA_HOME" ] ; then
    JAVACMD=$JAVA_HOME/bin/java
else
    JAVACMD=java
fi

exec "$JAVACMD" \
  $DEFAULT_JVM_OPTS \
  $JAVA_OPTS \
  $GRADLE_OPTS \
  "-Dorg.gradle.appname=$APP_BASE_NAME" \
  -classpath "$CLASSPATH" \
  org.gradle.wrapper.GradleWrapperMain \
  "$@"

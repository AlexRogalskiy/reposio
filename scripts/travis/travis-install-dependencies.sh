#!/bin/sh
# Modified version of
# https://github.com/ckan/ckan/blob/master/bin/travis-install-dependencies

set -e
set -x

# Drop Travis' postgres cluster if we're building using a different pg version
TRAVIS_PGVERSION='9.1'

if [ ${PGVERSION} != ${TRAVIS_PGVERSION} ]
then
  sudo -u postgres pg_dropcluster --stop ${TRAVIS_PGVERSION} main
fi

# Install PostgreSQL from apt.postgresql.org
sudo apt-get update -qq
sudo apt-get install postgresql-${PGVERSION} postgresql-contrib-${PGVERSION}

if [ ${PGVERSION} = '8.4' ]
then
  # force postgres to use 5432 as it's port
  sudo sed -i -e 's/port = 5433/port = 5432/g' /etc/postgresql/8.4/main/postgresql.conf
fi

sudo service postgresql restart ${PGVERSION}

sudo tail /var/log/postgresql/postgresql-${PGVERSION}-main.log

# Setup postgres' users and databases
sudo -u postgres psql -c "CREATE USER pgjdbc WITH PASSWORD 'test';"
sudo -u postgres psql -c 'CREATE DATABASE test WITH OWNER pgjdbc;'

# Install hstore extension if >= 9.1
if [ "${PGVERSION}" != '8.4' -a "${PGVERSION}" != '9.0' ]
then
  sudo -u postgres psql test -c 'CREATE EXTENSION hstore;'
fi
from node:latest
RUN apt-get update
RUN apt-get install -y nginx
RUN npm install -g npm
RUN npm install -g newman
RUN npm install -g newman newman-reporter-htmlextra


ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001

# Install packages and create user
RUN apt-get -y update \
&& groupadd -g ${container_user_gid} ${container_user_group} \
&& useradd -u ${container_user_uid} -g ${container_user_group} -s /bin/sh -m ${container_user}

# Permissions
RUN chown -R ${container_user}:${container_user} /home/${container_user}

# Select container user for all tasks
USER ${container_user_uid}:${container_user_gid}

WORKDIR  /home/${container_user}
COPY onboarding.postman_collection.json .
COPY default.sh .
COPY onboarding.postman_environment.json .
COPY entrypoint.sh .

ENV MYDIR=`pwd`
ENV DATE="$(date --utc +%FT%T.%3NZ)"
ENV URL=
ENV CERT_MANAGER=mosip-deployment-client
ENV CERT_MANAGER_PASSWORD=

ENTRYPOINT ["./entrypoint.sh"]

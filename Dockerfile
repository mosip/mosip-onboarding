FROM node:lts-alpine3.17
RUN npm install -g npm newman newman-reporter-htmlextra pem-jwk http-server
RUN apk add curl && \
    apk add openssl && \
    apk add jq

ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001

# Install packages and create user
RUN addgroup -g ${container_user_gid} ${container_user_group} \
&& adduser -u ${container_user_uid} -G ${container_user_group} -s /bin/bash -D ${container_user}

WORKDIR  /home/${container_user}
COPY --chown=${container_user}:${container_user} certs/ ./certs/
COPY *.json ./
COPY *.sh ./

RUN chmod +x certs/*.sh
RUN chmod +x *.sh

# Permissions
RUN chown -R ${container_user}:${container_user} /home/${container_user}

# Select container user for all tasks
USER ${container_user_uid}:${container_user_gid}

ENV MYDIR=`pwd`
ENV DATE="$(date --utc +%FT%T.%3NZ)"
ENV URL=
ENV CERT_MANAGER=mosip-deployment-client
ENV CERT_MANAGER_PASSWORD=
ENV ENABLE_INSECURE=false

ENTRYPOINT ["./entrypoint.sh"]

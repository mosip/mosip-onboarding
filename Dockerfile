FROM node:lts-alpine3.17

# can be passed during Docker build as build time environment variable for mosip user level change.
ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001

# can be passed during Docker build as build time environment for label related addition to docker.
ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME

# can be passed during Docker build as build time environment for label.
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

WORKDIR  /home/${container_user}
COPY --chown=${container_user}:${container_user} certs/ ./certs/
COPY *.json ./
COPY *.sh ./

# Install required packages using 'apk'
RUN npm install -g npm newman newman-reporter-htmlextra pem-jwk \
&& apk add curl \
&& apk add openssl \
&& apk add jq \
&& curl https://dl.min.io/client/mc/release/linux-amd64/mc -o /bin/mc \
&& chmod +x /bin/mc \
&& apk update && apk add --no-cache curl bash \
# Install kubectl binary
&& curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
&& chmod +x kubectl \
&& mv kubectl /usr/local/bin/ \
# Install packages and create user
&& addgroup -g ${container_user_gid} ${container_user_group} \
&& adduser -u ${container_user_uid} -G ${container_user_group} -s /bin/bash -D ${container_user} \
&& chmod +x certs/*.sh \
&& chmod +x *.sh \
&& chown -R ${container_user}:${container_user} /home/${container_user}

# Select container user for all tasks
USER ${container_user_uid}:${container_user_gid}

ENV MYDIR=`pwd`
ENV DATE="$(date --utc +%FT%T.%3NZ)"
ENV ENABLE_INSECURE=false
ENV MODULE=

ENV s3-host=
ENV s3-region=
ENV s3-user-key=
ENV s3-user-secret=
ENV s3-bucket-name=

ENV ns_mimoto=
ENV ns_esignet=

ENTRYPOINT ["./entrypoint.sh"]

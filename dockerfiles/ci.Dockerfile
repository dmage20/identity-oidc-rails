FROM public.ecr.aws/docker/library/ruby:4.0.5-bookworm

ENV NODE_MAJOR 22

RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list

RUN apt-get update -qq
RUN apt-get install -y --no-install-recommends nodejs \
      locales
RUN  curl -L -o cf8-cli_linux_x86-64.tgz "https://packages.cloudfoundry.org/stable?release=linux64-binary&version=v8&source=github" && \
      tar -xvzf cf8-cli_linux_x86-64.tgz && \
      mv cf8 /usr/local/bin && \
      cf8 --version

RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true

# syntax=docker/dockerfile:1

# Production image. Build and run by hand:
# docker build -t identity_oidc_rails .
# docker run -d -p 9292:9292 -e SECRET_KEY_BASE=<generated> --name identity_oidc_rails identity_oidc_rails

# Make sure RUBY_VERSION matches the Ruby version in .ruby-version
ARG RUBY_VERSION=4.0.5
FROM docker.io/library/ruby:$RUBY_VERSION AS base

ENV BUNDLER_VERSION="2.6.9"
ENV NODE_MAJOR=22

WORKDIR /code

ENV RAILS_ENV=production \
    BUNDLE_DEPLOYMENT=1 \
    BUNDLE_PATH=vendor/bundle \
    BUNDLE_WITHOUT="development test"

# Node is only needed to install USWDS into public/vendor
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
    apt-get update -qq && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends nodejs locales && \
    rm -rf /var/lib/apt/lists/*

RUN gem install bundler --version $BUNDLER_VERSION

COPY Gemfile Gemfile.lock ./
RUN bundle check || bundle install --jobs=4 --retry=3

COPY package.json package-lock.json ./
RUN npm ci

COPY . /code

RUN cp .env.example .env && \
    mkdir -p public/vendor && \
    cp -R node_modules/@uswds/uswds/dist public/vendor/uswds && \
    SECRET_KEY_BASE_DUMMY=1 bundle exec rails assets:precompile

EXPOSE 9292

CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "9292"]

# Copyright 2023 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG PYTHON_VERSION=3.10

FROM python:$PYTHON_VERSION

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

USER root

# Install Poetry
ARG POETRY_VERSION=1.4.2
RUN curl -sSL https://install.python-poetry.org | \
  POETRY_VERSION=$POETRY_VERSION POETRY_HOME=/opt/poetry python3 - && \
  cd /usr/local/bin && \
  ln -s /opt/poetry/bin/poetry && \
  poetry config virtualenvs.create false

# Install Uvicorn 
ARG UVICORN_VERSION=0.22.0
RUN pip install --no-cache-dir "uvicorn[standard]==$UVICORN_VERSION"

COPY ./scripts/start.sh /start.sh
RUN chmod +x /start.sh

# Use /aliro_actuator to host app
WORKDIR /aliro_actuator/
ENV PYTHONPATH=/aliro_actuator

# Set INSTALL_DEV to true to install development dependencies 
ARG INSTALL_DEV="false"

# Install spell checker when used for development
RUN if [ "$INSTALL_DEV" = "true" ] ; \
    then  curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
          apt install -y nodejs && \
          apt clean all && \
          npm install -g npm@latest && \
          npm install -g cspell@latest ; \
    fi


# Install git when used for development
RUN if [ "$INSTALL_DEV" = "true" ] ; \
    then  apt install -y git && \
          apt clean all ; \
    fi      

# Allow installing dev dependencies to run tests
# Copy poetry dependecy files and install dependencies
# We copy install dependencies before copying all app source to reuse the dependency install step in docker.
COPY ./pyproject.toml ./poetry.lock* /aliro_actuator/
RUN if [ "$INSTALL_DEV" = "true" ] ; \
        then poetry install --no-interaction --no-root  --no-ansi ; \     
        else poetry install --no-interaction --no-root --only main --no-ansi ; \
    fi

# Run the start script, it will check for an /aliro_actuator/prestart.sh script (e.g. for migrations)
# And then will start Uvicorn
CMD ["/start.sh"]

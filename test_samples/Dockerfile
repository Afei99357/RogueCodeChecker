FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl

# Dangerous practice: piping remote script directly to bash
RUN curl -fsSL http://example.com/install.sh | bash

USER root
EXPOSE 22


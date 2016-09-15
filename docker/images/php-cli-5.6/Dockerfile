FROM php:5.6.23-cli

RUN apt-get update && \
    apt-get install -y \
        libmcrypt-dev \
        libjpeg-dev \
        libpng12-dev \
        libicu-dev \
        libxml2-dev \
        libcurl4-openssl-dev \
        libssl-dev && \
    docker-php-ext-install -j$(nproc) bcmath mcrypt gd curl pdo pdo_mysql soap intl mbstring zip mysqli

RUN apt-get install -y less mysql-client

RUN useradd --create-home --shell /bin/bash wp
USER wp
WORKDIR /home/wp

ENV PATH=$PATH:/home/wp/bin

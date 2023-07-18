# Use the official PHP image as the base image
FROM php:8.2.4-apache-bullseye

# Set the working directory in the container

WORKDIR /var/www

# Copy the application files into the container
COPY . .

ENV COMPOSER_ALLOW_SUPERUSER=1

COPY --from=composer /usr/bin/composer /usr/bin/composer

# Install necessary PHP extensions
RUN apt-get update && apt-get install -y \
    libicu-dev \
    libzip-dev \
	sqlite3 \
	nano \
	curl \
	git \
	sudo \
	libcurl4-openssl-dev \
	libpq-dev \
	default-mysql-client \
    && docker-php-ext-install \
    intl \
    zip \
	curl \
    mysqli \
	pdo \
	pdo_mysql \
	pdo_pgsql \
	&& docker-php-ext-enable mysqli \
	&& docker-php-ext-enable pdo_mysql \
	&& docker-php-ext-enable pdo_pgsql \
    && a2enmod rewrite headers \
    && service apache2 restart \
    && chown -R www-data /var/www/ \
    && chgrp -R www-data /var/www/ \
    && chmod -R g+s /var/www/ \
    && find /var/www/ -type d -exec chmod 0775 {} \; \
    && find /var/www/ -type f -exec chmod 0664 {} \; \
    && mkdir /var/mvc \
	&& cd /var/mvc \
	&& mkdir app \
	&& mkdir plugins \
	&& mkdir uploads \
	&& mkdir /var/mvc/app/controllers \
	&& chown -R www-data:www-data uploads \
	&& cd /var \
	&& chmod -R 777 mvc \
	&& cd /var/www/ \
	&& rm -r html \
	&& mv public html \
	&& chmod 777 writable \
    && composer install \
	&& echo "done" 
    

# Expose port 80 and 443
EXPOSE 80

EXPOSE 443

# Define the entry point for the container
CMD ["apache2-foreground"]

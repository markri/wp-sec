markri/wp-sec
=============


[![Build Status](https://travis-ci.org/markri/wp-sec.svg?branch=master)](https://travis-ci.org/markri/wp-sec)

Quick links: [Using](#using) | [Installing](#installing) | [Contributing](#contributing)

## What is wp-sec?

Wp-sec is an extension for wp-cli which checks for Wordpress CVE security issues at wpvulndb.com. All installed versions
of core, plugins and themes can be checked and monitored, so you know when to update your Wordpress installation.

## Using

Following synopsis should be enough to get you started

    NAME

      wp wp-sec

    DESCRIPTION

      Check for CVE security issues at wpvulndb.com

    SYNOPSIS

      wp wp-sec <command>

    SUBCOMMANDS

      check      Checks for core, plugins and themes
      version    Returns current version


    CHECK PARAMETERS

      --type=[core|plugins|themes|all]
          Check for a specific part, or use all to check all parts
          Default: all

      --output=[user|nagios|json]
          Controls the output
          Default: user

      --cached
          Lets you cache the resuls of wpvulndb, to prevent hammering at their servers. Be nice to them, it's a free service

      --ttl=[integer]
          Cache control of above --cached setting. If omitted a default of 8 hours is used. This setting will give
          you fine grained control. Value is entered in seconds

      --lowercase
          Converts themes and plugin names to lowercase to submit to wpvulndb
 
    GLOBAL PARAMETERS

      All global wp cli parameters are inherited



## Installing

Installing this package requires WP-CLI v0.23.0 or greater. Install fresh wp-cli as instructed [here](http://wp-cli.org/#installing)
Or update to the latest stable release with `wp cli update`.

Once you've done so, you can install this package with `wp package install markri/wp-sec`.


## Contributing

We appreciate you taking the initiative to contribute to this project.

Contributing isn’t limited to just code. We encourage you to contribute in the way that best fits your abilities, by 
writing tutorials, giving a demo at your local meetup, helping other users with their support questions, or revising our
 documentation.

## Development

To setup a development environment for code contributions, follow instructions below. Execution of the extension is done
within a dockerized environment (only tested under Linux). Editing can still be done outside of docker as the current directory is mounted into
the docker environment.

Place wp-cli binary in the bin folder. According to current documentation from WP-CLI you would want to do something 
like: 
       
       cd bin 
       curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
       chmod +x wp-cli.phar
       mv wp-cli.phar wp
       
Create a docker environment and bring it up like this:
   
       docker-compose up -d
       
Enter your dev environment and create a fresh wordpress installation to test against

       docker exec -ti wpsec-phpcli /bin/bash
       
[Install composer](https://getcomposer.org/download/) and run

       mkdir testsite && cd testsite
       wp core download
       wp core config --dbname=database --dbuser=user --dbpass=password --dbhost=wpsec-mysql
       wp core install --url=http://localhost --title=testsite --admin_user=admin --admin_password=admin --admin_email=mail@mail.com --skip-email
       
Running

       wp wp-sec check
       
Running testsuite
       
       vendor/bin/behat --strict
          

### Reporting a bug

Think you’ve found a bug? We’d love for you to help us get it fixed.

Before you create a new issue, you should [search existing issues](https://github.com/markri/wp-sec/issues?q=label%3Abug%20) 
to see if there’s an existing resolution to it, or if it’s already been fixed in a newer version.

Once you’ve done a bit of searching and discovered there isn’t an open or fixed issue for your bug, please 
[create a new issue](https://github.com/markri/wp-sec/issues/new) with the following:

1. What you were doing (e.g. "When I run `wp post list`").
2. What you saw (e.g. "I see a fatal about a class being undefined.").
3. What you expected to see (e.g. "I expected to see the list of posts.")

Include as much detail as you can, and clear steps to reproduce if possible.

### Creating a pull request

Want to contribute a new feature? Please first [open a new issue](https://github.com/markri/wp-sec/issues/new) to 
discuss whether the feature is a good fit for the project.

Once you've decided to commit the time to seeing your pull request through, please follow our guidelines for creating a 
pull request to make sure it's a pleasant experience:

1. Create a feature branch for each contribution.
2. Submit your pull request early for feedback.
3. Include functional tests with your changes. [Read the WP-CLI documentation](https://wp-cli.org/docs/pull-requests/#functional-tests) for an introduction.
4. Follow the [PSR-2 Coding Standards](http://www.php-fig.org/psr/psr-2/).




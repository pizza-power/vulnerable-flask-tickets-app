# flask tickets

A flask-based ticketing system that has/will have some intentional security issues. 

## Installation

clone this repo

## running

You'll need a postgres container/installation running. Use the following docker-compose file to run this app with a postgres container. 

start the db with the docker compose file

    $ docker-compose up

Start the server

    $ python3 wsgi.py

You may need to edit some paths that are hardcoded into the app and/or some other minor setttings to get it working. 

#!/bin/sh
docker image build -t javatask/dss ./
docker container run -it --publish 8081:8080 javatask/dss:latest

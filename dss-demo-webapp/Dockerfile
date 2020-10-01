# we are extending everything from tomcat:8.0 image ...
FROM tomcat:8.5

MAINTAINER javatask
# COPY path-to-your-application-war path-to-webapps-in-docker-tomcat
# RUN rm /usr/local/tomcat/webapps/ROOT.war
ADD target/dss-demo-webapp-5.7.1.war /usr/local/tomcat/webapps/dss-webapp.war
COPY web.xml /usr/local/tomcat/conf/

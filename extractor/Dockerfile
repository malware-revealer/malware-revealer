FROM ubuntu:18.04

ENV APP_PATH /opt/extractor/

# Install requirements
RUN apt-get update
RUN apt-get install -y python3 python3-pip
# Install python modules
RUN pip3 install lief
RUN apt-get install -y python3-yaml
RUN pip3 install numpy
RUN pip3 install Pillow

# Copy source files
RUN mkdir $APP_PATH
WORKDIR $APP_PATH
COPY . $APP_PATH

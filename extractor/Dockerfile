FROM ubuntu:18.04

ENV APP_PATH /opt/extractor/

# Install requirements
RUN apt-get update && apt-get install -y python3 python3-pip python3-yaml
# Install python modules
COPY requirements.txt /
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy source files
RUN mkdir $APP_PATH
WORKDIR $APP_PATH
COPY . $APP_PATH

# Execute the extractor by default
ENTRYPOINT ["python3", "extract.py"]

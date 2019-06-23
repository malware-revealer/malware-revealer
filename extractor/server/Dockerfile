FROM malwarerevealer/extractor

ENV APP_PATH /opt/extractor/

# install python packages
COPY requirements.txt /
RUN pip3 install --no-cache-dir -r /requirements.txt

# setup app dir
WORKDIR $APP_PATH
COPY / $APP_PATH

ENTRYPOINT ["python3", "app.py"]

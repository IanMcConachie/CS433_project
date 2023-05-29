FROM python:3.8
LABEL maintainer="eliotm@uoregon.edu"
RUN apt-get update && apt-get install -y libgl1-mesa-glx
COPY . /client
WORKDIR /client
RUN pip install -r requirements.txt
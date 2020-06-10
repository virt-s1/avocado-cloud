FROM fedora:28

# metadata
LABEL author="Charles Shih"
LABEL maintainer="cheshi@redhat.com"
LABEL version="2.0"
LABEL description="This image provdes a running environment for avocado_cloud tests."

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE 1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED 1

# configure application
WORKDIR /app

# install basic packages
RUN dnf install -y ncurses iputils \
    make gcc gcc-c++ \
    redhat-rpm-config \
    openssh-clients \
    python python-devel \
    python-avocado

# install pip requirements
ADD ./container/requirements_base.txt ./container/requirements_base.txt
RUN python -m pip install -r ./container/requirements_base.txt

ADD ./container/requirements_others.txt ./container/requirements_others.txt
RUN python -m pip install -r ./container/requirements_others.txt

ADD ./container/requirements_aws.txt ./container/requirements_aws.txt
RUN python -m pip install -r ./container/requirements_aws.txt

ADD ./container/requirements_azure.txt ./container/requirements_azure.txt
RUN python -m pip install -r ./container/requirements_azure.txt

ADD ./container/requirements_alibaba.txt ./container/requirements_alibaba.txt
RUN python -m pip install -r ./container/requirements_alibaba.txt

# add avocado-cloud source code
ADD . /app

# install avocado-cloud
RUN python ./setup.py install

# Switching to a non-root user
#RUN useradd appuser && chown -R appuser /app
#USER appuser

# setup ssh
RUN mkdir -p /root/.ssh/
RUN cp ./container/ssh.config /root/.ssh/config

# create mount point
RUN mkdir -p /data
RUN mkdir -p /root/avocado/job-results

# Export volumes
VOLUME [ "/app" ]
VOLUME [ "/data" ]
VOLUME [ "/root/avocado/job-results" ]

# During debugging, this entry point will be overridden.
CMD ["/bin/bash"]

# Instructions for using avocado-cloud in a container

# Steps for using avocado-cloud

## 1. Install container runtime

### 1.1 Install Podman (recommand)

Recommend to use Podman in Red Hat distro. It can be installed by:

```
dnf install podman
```

### 1.2 Install Docker-CE (Alternative as you need)

Alternatively, you can use Docker as container runtime, please follow below article to install docker-ce:
[Get Docker CE for Fedora | Docker Documentation](https://docs.docker.com/install/linux/docker-ce/fedora/#install-docker-ce)

**Note:**
If you want to use `docker` as container runtime, just replace `podman` with `docker` in the following commands.

## 2. Get the latest avocado-cloud repo

```
git clone ssh://cheshi@code.engineering.redhat.com/avocado-cloud
```

## 3. Build the container image

```
cd avocado-cloud
podman build --rm --pull -t "avocado-cloud" . -f ./container/Dockerfile
```

**Note:**
This command will create a container image named "avocado-cloud" with tag `latest` on your host;

**Warning:**
The image will contain the avocado-cloud framework which is not currently published. So do NOT push this image to the public repositories, such as [Docker Repository](https://hub.docker.com/), etc.

## 4. Run as interactive container

### 4.1 Mount as "bind mount" (recommand)

```
# select a path to store your data and logs
cd <avocado-cloud workspace>

# select a name for your container
CONTAINER_NAME=actest

# create host directories
mkdir -p ./$CONTAINER_NAME/data
mkdir -p ./$CONTAINER_NAME/job-results
sudo chcon -Rt svirt_sandbox_file_t ./$CONTAINER_NAME/

# run an interactive container 
podman run --name $CONTAINER_NAME -it \
-v $PWD/$CONTAINER_NAME/data:/data:rw \
-v $PWD/$CONTAINER_NAME/job-results:/root/avocado/job-results:rw \
avocado-cloud:latest /bin/bash
```

**Note:**
This command will create a container named `$CONTAINER_NAME`, the following directories will be created under path `<avocado-cloud workspace>` to store the data:
1. `$CONTAINER_NAME/data`: store private data (ssh credentials, configure files, etc)
2. `$CONTAINER_NAME/job-results`: store the test logs and results

### 4.2 Mount as volumes (alternative as you need)

```
# select a name for your container
CONTAINER_NAME=actest

# remove the app volume as you need
# podman volume rm ${CONTAINER_NAME}-app

# run an interactive container
podman run --name $CONTAINER_NAME -it \
--mount type=volume,source=${CONTAINER_NAME}-app,destination=/app \
--mount type=volume,source=${CONTAINER_NAME}-data,destination=/data,ro=true \
--mount type=volume,source=${CONTAINER_NAME}-job-results,destination=/root/avocado/job-results \
avocado-cloud:latest /bin/bash
```

**Note:**
This command will create a container named `$CONTAINER_NAME`, the following directories will be created under path `$HOME/.local/share/containers/storage/volumes/` to store the data files:
1. `${CONTAINER_NAME}-app`: store the source code of avocado-cloud
2. `${CONTAINER_NAME}-data`: store private data (ssh credentials, configure files, etc)
3. `${CONTAINER_NAME}-job-results`: store the test logs and results

**Warning:**
Volume `${CONTAINER_NAME}-app` will be reused if it already exists, in this case, it will overwrite the contents of `/app` on the image.

## 5. Run your test

Keep this terminal being opened, you will be able to interact with your container and run tests from this terminal. (If you closed this terminal, seek help from the "Tips" session of this instruction)

### Alibaba Cloud

#### For the first time

If there is nothing under `$CONTAINER_NAME/data` of your host. You will need to init the environment before running tests, do the following steps:
1. Put your ssh credential (the `.pem` file) under `$CONTAINER_NAME/data`;
2. Run script `/app/container/bin/general_setup.sh`. It will init the environment for the cloud.
3. Update the `.yaml` files under `$CONTAINER_NAME/data` to customize your testing;

Now, you can run `/app/container/bin/test_alibaba.sh` to start your tests for Alibaba Cloud, you will be able to get all the test results and logs from `$CONTAINER_NAME/job-results`.

#### Based on privous test

If there is everything under `$CONTAINER_NAME/data` of your host. You can directly run `/app/container/bin/test_alibaba.sh` to start your tests for Alibaba Cloud, you will be able to get all the test results and logs from `$CONTAINER_NAME/job-results`.

#### A step further (non-interactive / scripting)

You must have known how it works, so you can prepare all your needs under `$CONTAINER_NAME/data` and trigger the tests directly.

```
# prepare all the files you need
$ ll ./$CONTAINER_NAME/data
total 28
-rw-r--r--. 1 cheshi cheshi  692 May 25 23:28 alibaba_common.yaml
-rw-r--r--. 1 cheshi cheshi  183 May 25 23:29 alibaba_flavors.yaml
-rw-r--r--. 1 cheshi cheshi  292 May 26 10:10 alibaba_testcases.yaml
-r--------. 1 cheshi cheshi 1704 May 25 16:47 cheshi-docker.pem

# trigger tests with an instant container
podman run --rm --name $CONTAINER_NAME -it \
-v $PWD/$CONTAINER_NAME/data:/data:rw \
-v $PWD/$CONTAINER_NAME/job-results:/root/avocado/job-results:rw \
avocado-cloud:latest /bin/bash /app/container/bin/test_alibaba.sh
```

**Note:**
Option `--rm` helps you remove the container once the tests finished.

# Tips for using avocado-cloud in container

If you use interactive container, just treat it as physical host. Meanwhile there are some tips for you to play with the container.

Tips:  
1. Put the container to the background: press `Ctrl-P` then `Ctrl-Q`;
2. Put a container back to the foreground: `podman attach <CONTAINER_NAME>`;
3. Leave a container and make it stopped: just execute `exit` command;
4. Start a stopped container: execute `podman start <CONTAINER_NAME>`;
5. Open another terminal on a running container: `podman exec -it <CONTAINER_NAME> /bin/bash`;
6. List all the containers on your system: `podman ps -a`;
7. List all the volumes on your system: `podman volume ls`

All the avocado-cloud logs will be generated under `$CONTAINER_NAME/job-results`. The data stored in this directory will never be lost no matter the container is alive or not, even it has been destoryed.

# Enjoy it

Feel free to [reach me](mailto:cheshi@redhat.com) if you have further questions.

# Using the TLS-Docker-Library

The [TLS-Docker-Library](https://github.com/tls-attacker/Tls-docker-library) is a set of Dockerfiles and scripts for building and running many different TLS implementations.
It can be used to test example server and client implementations of various TLS libraries.

You can follow the README file of the repository to learn, how to build the docker containers yourself.

In short, you need to
 - run `./setup.sh` to generate the base images and certificates
 - go to `cd src/main/resources/images`
 - run `python3 build.py -l image-name:version` with the name of the implementation as well as the version you would like to build
   - if you would like to build the newest version use `:latest`

## Testing Built Library Containers using TLS-Anvil
Once you built an image of a library you'd like to test, we have to create and start the container and then connect it to TLS-Anvil.

This procedure differs between server and client images.

To see how to create and run a container of your desired implementation, go to the subfolder of that implementation where you will find a readme file with more infos.

### Server Images
Server images almost always just start a binary server example implementation of that library in a loop.

The arguments you pass to the docker container after the image name will get passed to the server executable. E.g. the image `openssl-server:1.1.1i` has the entrypoint `openssl s_server`. Any arguments that you pass after `docker run openssl-server:1.1.1i ...` are passed to the openssl executable.

Many of the server implementations need certificates. Many certificates were created when you ran `./setup.sh`. Those are stored in the docker volume `cert-data` and can be used with any image.

E.g. to start an OpenSSL server with an RSA certificate we can use:

`docker run -v cert-data:/certs/ openssl-server:1.1.1i -port 8443 -cert /certs/rsa2048cert.pem -key /certs/rsa2048key.pem`

The `-v` option bind the `cert-data` volume to the container at the location `/certs/`.

The server is now listening on port 8443, but since it is a container, the port is only accessible from inside the container. To be able to connect to it we have to:
 - add the server container and TLS-Anvil container to the same docker network (like in our [example](/docs/Quick-Start/Server-Testing))
 - expose the port using `-p 8443:8443` or
 - add the docker container to the host network using `--network host`

If you added it to a network, the server will be reachable with its container name (can be changed by using `--name ...`), or via the other options, it should be reachable via `localhost:8443`.
This is, what you will need to input in the `-connect ...` parameter of TLS-Anvil.

### Client Images
Client images implement a small web server that listens on port 8090. Command line arguments that you pass behind the image name also get passed directly to the client executable. But the client executable is not running in a loop, but rather only started when a GET request is sent to the `/trigger` endpoint of the webserver.

E.g. to start the OpenSSL client, we can run `docker run openssl-client:1.1.1i -connect localhost:8443` and the `-connect ...` part is directly passed to `openssl s_client`.

You have to make sure, that TLS-Anvil can reach the webserver (port 8090) of the client image, and the client can reach TLS-Anvil to connect to. This can be done by either:
 - adding the client container and TLS-Anvil container to the same docker network (like in our [example](/docs/Quick-Start/Client-Testing))
   - the client can then connect to TLS-Anvil using its container name
   - TLS-Anvil can connect to the client using its container name
 - exposing port the port 8090 on the client using `-p 8090:8090` and exposing the server listening port on the TLS-Anvil container if also run via docker
   - the client can then connect to TLS-Anvil using the ip `172.17.0.1` or `host.docker.internal`
   - TLS-Anvil can reach the container using `172.17.0.1` or `host.docker.internal` if also run in a container or `localhost` if run in the host
 - adding the client (and TLS-Anvil) to the host network using `--network host`
   - the client can then connect to TLS-Anvil using `localhost`
   - TLS-Anvil can also connect to the client using `localhost`

TLS-Anvil uses a *trigger script* in the client testing mode. The script is called every time it wants the client to connect to it. Using the TLS-Docker-Library images you almost always want to use `curl` in the trigger script to connect to the `/trigger` endpoint of the client.

An example would be `docker run --network host -v $(pwd):/output/  ghcr.io/tls-attacker/tlsanvil:latest client -port 8443 -triggerScript curl localhost:8090/trigger`.

:::info

You could also execute a binary of a client implementation directly in the `-triggerScript` parameter.

:::
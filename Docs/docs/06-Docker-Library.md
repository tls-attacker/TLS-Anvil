# Using the TLS-Docker-Library

The [TLS-Docker-Library](https://github.com/tls-attacker/Tls-docker-library) is a collection of Dockerfiles and scripts for building and running various TLS implementations.  
It can be used to test example server and client implementations of multiple TLS libraries.

Refer to the repository's README file to learn how to build the Docker containers yourself.

In brief, the steps are:
- Run `./setup.sh` to generate the base images and certificates.
- Navigate to `src/main/resources/images`.
- Run `python3 build.py -l image-name:version` specifying the implementation name and version you want to build.
   - To build the latest version, use the `:latest` tag.

## Testing Built Library Containers Using TLS-Anvil

After building an image of the desired library, you need to create and start the container, then connect it to TLS-Anvil.

The process differs for server and client images.

To learn how to create and run a container for a specific implementation, go to that implementation’s subfolder, where you will find a README with detailed instructions.

### Server Images

Server images typically launch a binary server example of the library in a loop.

Arguments passed to the Docker container after the image name are forwarded to the server executable. For example, the image `openssl-server:1.1.1i` uses the entrypoint `openssl s_server`. Any arguments you pass after `docker run openssl-server:1.1.1i ...` are passed to the `openssl` executable.

Many server implementations require certificates, which are generated when you run `./setup.sh`. These certificates are stored in the Docker volume `cert-data` and can be used with any image.

For example, to start an OpenSSL server with an RSA certificate:

```
docker run -v cert-data:/certs/ openssl-server:1.1.1i -port 8443 -cert /certs/rsa2048cert.pem -key /certs/rsa2048key.pem
```

The `-v` option binds the `cert-data` volume to the container at `/certs/`.

The server will listen on port 8443 inside the container. Since the container’s ports are isolated, to connect externally you must:

- Add both the server container and TLS-Anvil container to the same Docker network (see our [example](/docs/Quick-Start/Server-Testing))
- Or expose the port with `-p 8443:8443`
- Or add the container to the host network using `--network host`

If using a Docker network, the server will be reachable via its container name (which you can set with `--name ...`). Otherwise, if you expose the port or use the host network, it will be reachable via `localhost:8443`.  
This address is what you should use in TLS-Anvil’s `-connect ...` parameter.

### Client Images

Client images run a small web server that listens on port 8090. Command-line arguments passed after the image name are forwarded to the client executable. However, unlike server images, the client executable runs only when a GET request is sent to the `/trigger` endpoint of the web server.

For example, to start the OpenSSL client:

```
docker run openssl-client:1.1.1i -connect localhost:8443
```

The `-connect ...` argument is passed directly to `openssl s_client`.

You must ensure TLS-Anvil can access the client’s web server (port 8090), and the client can reach TLS-Anvil to connect. This can be done by:

- Adding the client and TLS-Anvil containers to the same Docker network (see our [example](/docs/Quick-Start/Client-Testing))
   - The client can connect to TLS-Anvil using its container name
   - TLS-Anvil can connect to the client using its container name
- Exposing port 8090 on the client with `-p 8090:8090` and exposing the server listening port on the TLS-Anvil container (if also run in Docker)
   - The client can connect to TLS-Anvil using the IP `172.17.0.1` or `host.docker.internal`
   - TLS-Anvil can reach the client container using `172.17.0.1` or `host.docker.internal` (if in a container), or `localhost` (if run on the host)
- Adding the client (and TLS-Anvil) to the host network using `--network host`
   - The client can connect to TLS-Anvil using `localhost`
   - TLS-Anvil can connect to the client using `localhost`

In client testing mode, TLS-Anvil uses a *trigger script* that it calls whenever it wants the client to connect.  
When using TLS-Docker-Library images, the trigger script typically uses `curl` to access the client’s `/trigger` endpoint.

For example:

```
docker run --network host -v $(pwd):/output/ ghcr.io/tls-attacker/tlsanvil:latest client -port 8443 -triggerScript curl localhost:8090/trigger
```

:::info

You can also execute a client implementation binary directly in the `-triggerScript` parameter.

:::

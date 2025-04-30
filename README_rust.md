
# katzepost_thinclient

*A thin client for sending and receiving messages via a Katzenpost mix network.*

This crate provides a thin client library for interacting with a
Katzenpost mixnet.

A mix network is a type of anonymous communications network.

A thin client library is code you can use as a depencency in your
application so that it can anonymously interact with services on the
mix network. The Katzenpost client daemon is a multiplexing client;
many applications on the same device can use their thin client
libraries to connect to the daemon and interact with mixnet services
concurrently.



## Contributions

This is a work in progress and we'll require feedback from developers to make improvements.
Pull requests welcome:

https://github.com/katzenpost/thin_client



## Documentation

* Rust API docs https://docs.rs/katzenpost_thin_client/0.0.4/katzenpost_thin_client/

* Katzenpost client integration guide https://github.com/katzenpost/website/blob/main/content/en/docs/client_integration.md



## 📦 Installation

Add katzenpost_thin_client to your `Cargo.toml`:

```toml
[dependencies]
katzenpost_thin_client = "0.0.4"
```


## Code Example

Here's well use the docker mixnet to test locally.
Our example rust mixnet client is here:

* https://github.com/katzenpost/thin_client/blob/main/examples/echo_ping.rs

Firstly, start the docker mixnet. For details instructions, go here:
https://katzenpost.network/docs/admin_guide/docker.html We'll be
working with the Katzenpost monorepo to get the docker mixnet started:
https://github.com/katzenpost/katzenpost

```bash

cd katzenpost/docker
make start wait run-ping
```

Once our docker mixnet is fully started up then we can start the client2 daemon:

```bash

cd katzenpost/client2
make warpedclientdaemon
cd cmd/kpclientd
./kpclientd -c ../../../docker/voting_mixnet/client2/client.toml
```

The above client2/client.toml should have been created by the `make
start` command above which sets up a new docker mixnet. Next we can
finally run our example rust client, specifying the correct file path
to the thin client configuration file:


```bash

cargo run --example echo_ping -- ./katzenpost/docker/voting_mixnet/client2/thinclient.toml
```


## Compatibility

Works with Katzenpost v0.0.49 or later.



## License

AGPLv3

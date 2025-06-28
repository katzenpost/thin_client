
# katzenpost_thinclient

*A thin client for sending and receiving messages via a Katzenpost mix network.*

This pypi package provides a thin client library for interacting with a
Katzenpost mixnet.

A mix network is a type of anonymous communications network.

A thin client library is code you can use as a depencency in your
application so that it can anonymously interact with services on the
mix network. The Katzenpost client daemon is a multiplexing client;
many applications on the same device can use their thin client
libraries to connect to the daemon and interact with mixnet services
concurrently.



# Contributions

This is a work in progress and we'll require feedback from developers to make improvements.
Pull requests welcome:

https://github.com/katzenpost/thin_client



# Documentation

Here's our python API docs:
https://katzenpost.network/docs/python_thin_client.html

Here's our thin client integration guide:
https://github.com/katzenpost/website/blob/main/content/en/docs/client_integration.md



# Installation

Install katzenpost using pip:

```bash
pip install katzenpost_thinclient
```

or

```bash
pip install -e .
```



# Running Code Examples

In the `tests/` directory AND the `examples/` directory you'll find
some simple python examples that use this library. However both of
them refer to the path to the katzenpost docker mixnet's client2's
thinclient's config, like so:

```python

docker_mixnet_thinclient_cfg = "../../katzenpost/docker/voting_mixnet/client2/thinclient.toml"
```

These examples are meant to be runned after starting a katzenpost docker mixnet.
Firstly, start the docker mixnet. For details instructions, go here: https://katzenpost.network/docs/admin_guide/docker.html
We'll be working with the Katzenpost monorepo to get the docker mixnet started: https://github.com/katzenpost/katzenpost

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

The above client2/client.toml should have been created by the docker Makefile
(via the `make start` command above) which sets up a new docker mixnet. Next we can
finally run our test and examples:


```bash

pytest
```

and

```bash

cd examples
python fetch_pki_doc.py
# blah blah informative output
python echo_ping.py
# blah blah informative output
```


# Additional Code Examples

We have two working example python programs that use this
thin client library:

1. stats - terminal application that prints the current mixnet status
   https://github.com/katzenpost/status

2. worldmap - renders an image of the mixnet transposed over a worldmap
   https://github.com/katzenpost/worldmap


# Compatibility

Works with Katzenpost v0.0.49 or later.



# License

AGPLv3

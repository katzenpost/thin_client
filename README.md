# thin client library for Katzenpost client daemon

*What is it?*

**work-in-progress thin client library for both rust and python**

## rust


## python

before you run the python thin client integraton tests, first
start up the katzenpost docker test mixnet:

```bash
git clone https://github.com/katzenpost/katzenpost.git
cd katzenpost
cd docker
make start wait run-ping
cd ..
```

start a katzenpost client2 daemon:
```bash
cd katzenpost/client2
make warpedclientdaemon
./cmd/kpclientd/kpclientd -c ../docker/voting_mixnet/client2/client.toml

```

after the daemon is started, then run the pythoin thin client integration tests:

```
python -m pytest -v -s
```

this will work because presumably you've already actived your python venv (or whatever)
and done a `pip install -e .` from within this git repo in order to install the python package
and it's dependencies...


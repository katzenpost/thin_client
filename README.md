# thin client library for Katzenpost client daemon


**thin client library for python**

Works with Katzenpost v0.0.40 or later.


## rust not yet completed

## python


### building the client

before you run the python thin client integraton tests, first
start up the katzenpost docker test mixnet:

```bash
git clone https://github.com/katzenpost/katzenpost.git
cd katzenpost
cd docker
make start wait run-ping
cd ..
```

### running the client

start a katzenpost client2 daemon:
```bash
cd katzenpost/client2
make clientdaemon
./cmd/kpclientd/kpclientd -c client.toml

```


### development testing of the client

after the daemon is started, then run the pythoin thin client integration tests:

```
python -m pytest -v -s
```

this will work because presumably you've already actived your python venv (or whatever)
and done a `pip install -e .` from within this git repo in order to install the python package
and it's dependencies...



# License

AGPLv3

# thin client library for Katzenpost client daemon


before you run the python thin client integraton tests, first
start up the katzenpost client2 daemon:

```bash

git clone https://github.com/katzenpost/katzenpost.git
cd katzenpost
git checkout client2

cd docker
make start
make wait run-ping
cd ..

cd client2
make warpedclientdaemon

./cmd/kpclientd/kpclientd -c ../docker/voting_mixnet/client2/client.toml

```


after the daemon is started, then run the integration tests:


```
python -m pytest -v -s
```

this will work because presumable you've already actived your python venv (or whatever)
and done a `pip install -e .` from within this git repo in order to install the python package
and it's dependencies...


# Python Mining Client Demo

This program implements all the client-side functionality for mining clients
*EXCEPT* for heartbeats. It will connect to the server, request work, mine a
block, and then exit after verification.

To be able to run it, you'll need the python protobuf library:

```
sudo pacman -Sy python-protobuf
```


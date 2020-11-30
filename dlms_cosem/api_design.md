# API Design

We want a simple API for the actions you perform on objects in a DLMS meter.
DLSM follows a request/response flow.

Simillar to how redis can pipeline actions there is the possiblite to "pipeline" 
commands in DLMS with the ACCESS service where several actions can 
be "clumped together in on request" 

The client should take care of association aquire and release without the user needing 
to set it up. It should also be possible to set up a predefined assosiation and skip the 
aquire and release.

```python 
with Client() as client:
    response = client.set("1.2.3.4.5", 2, "test")
``` 

But this is a bit too simple since we need to know how to model the objects in the meter.

There should be a way of defining the objects available in the meter beforehand or 
set it up as the request goes away. Then if something is wrong in the calling a proper 
error can be generated. 

```python 
with Client() as client:
    response = client.set(
        logical_name=LogicalNameReference(a=1, b=2, c=3, d=4, e=5, f=5)
        interface=PushInterfaceV2,
        attribute=2,
        value="test"
        )
    # above should be the same as
    response = client.set("1.2.3.4.5", 2, "test") 
    # if we know that the PushInterface is on LN 1.2.3.4.5 beforehand
    # It could be a simple dict.

    # it would also make it possible to use something like:
    response = client["1.2.3.4.5"][0] # to initate a get in the attribute.
    # or
    response = client["1.2.3.4.5"].set(2, "test")
    
``` 

Since we want automatic handling of assiciation aquire and relase we need to set up 
the client with data so it can handle it for us.

```python

with Client(encryption_key="0f0f", security_setup=x, proposed_conformance=Conformance() as client:
    response = client.set("1.2.3.4.5", 2, "test")
```

Should result in an AARQ is sent according to association. Set up dedicated key 
encryption, handle HLS password transfer, etc.
When you then send a SET (WriteRequestApdu) it should be automatically encrypted 
with the global or dedicated key. If block is supported in conformance it should be 
split into blocks and sent. The response should be received and when it is fully 
received it should be decrypted and returned to the user. 

By having the "heavy stuff" handled in the background it makes it possbile to keep a 
simple API while adding incfreasing functionallity to the middlestack.

We also need to add a certain transport to the client so it can send its data to the 
meter. HDLC and IP should be implemented. Maybe HDLC_over_IP. But since that is in the 
IO part it can easily be broken out and extended as needed, supporting asyncio or 
whatever.

The main part of the protocol implementation should still be sans-io.

client.set()
 -> SetRequest
   -> GlobalCipheredApdu
      -> Block, Block, Block
      -> connection.send("data")
      -> data is sent over wire.
      <- data is received.
      <- Block, Block, Block
   <- GlobalCipheredApdu
 <- SetResponse

A simple test server to receive RFC9567 Error reports and display them.


Example query to test:

```
dig +ednsopt="15:000F68656C6C6F" @127.0.0.1 -p 5300 txt _er.1.failing.example.net.15._er.errors.example.com
```
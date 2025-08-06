A simple test server to receive RFC9567 Error reports and display them.

Build:

```
go build .
```

Example usage:

``` 
./dns-error-agent -zonename errors.example.com -ns ns1.example.com -txtresponse "Report received"
```

Example query to test:

```
dig +ednsopt="15:000F68656C6C6F" @127.0.0.1 -p 5300 txt _er.1.failing.example.net.15._er.errors.example.com
```

-> 

```
2025/08/06 13:56:51 Received report for QNAME: failing.example.net, QTYPE: 1(A), EDE CODE: 15
2025/08/06 13:56:51 Additional EDE information: 15 (Blocked): (hello)
```


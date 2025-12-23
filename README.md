Tecnocratica for [`libdns`](https://github.com/libdns/libdns)
========================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/he)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for Tecnocratica, Neodigit and Virtualname,
allowing you to manage DNS records.

This package uses the API at these places:
  - https://developers.neodigit.net/#dns
  - https://developers.virtualname.net/#dns

Configuration
=============

To configure, you need to get an API Token from your control panel.
Also depending on the control panel you're using, you may need to change the url

Neodigit:
  - https://api.neodigit.net/v1

Virtualname:
  - https://api.virtualname.net/v1

Example
=======

```go
package main

import (
    "context"
    "fmt"

    "github.com/libdns/tecnocratica"
)

func main() {
    provider := &tecnocratica.Provider{
        APIToken: "<API Token>",
        APIURL: "<The url of the control panel API>",
    }
    zone := "example.com."

    records, err := provider.GetRecords(context.TODO(), zone)

    if err != nil {
        fmt.Printf("Error: %s", err.Error())
        return
    }

    fmt.Println(records)
}
```
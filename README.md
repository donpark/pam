# pam

PAM interaction for Go.  Currently consists of functionality to implement your own module
for PAM to load/communicate with for each service.

## Install

> `go get github.com/zro/pam`

## Usage

Declare PAM request handling methods like this:

```go

  import "github.com/donpark/pam"
  
  type mypam struct {
    // your pam vars
  }

  func (mp *mypam) Authenticate(hdl pam.Handle, args pam.Args) pam.Value {
    fmt.Println("Authenticate:", args)
    return pam.Success
  }

  func (mp *mypam) SetCredential(hdl pam.Handle, args pam.Args) pam.Value {
    fmt.Println("SetCredential:", args)
    return pam.Success
  }

  var mp mypam

  func init() {
    pam.RegisterAuthHandler(&mp)
  }

  func main() {
    // needed in c-shared buildmode
  }
```

Build custom PAM shared library

    go build -buildmode=c-shared -o /lib64/security/pam_mypam.so main.go

For 32-bit env, `/lib/security` directory should be used.

## Credits

I looked off of [golang-pam-auth](https://github.com/AmandaCameron/golang-pam-auth) a bit for
initial coding of pam method translations.  Thanks has to go out to Amanda for her work here.
The conversation code is mostly pulled directly from hers.

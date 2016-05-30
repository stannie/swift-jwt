# swift-jwt
Swift Framework for JWT (JSON Web Token)

Created for Authentiq ID

## Installation

### Available in CocoaPods

SwiftJWT is available through [CocoaPods](http://cocoapods.org). To install it, simply add the following line to your Podfile:

```objc
pod "SwiftJWT"
```

In case you want to use the project with `Ed25519` algorithm support, you can install it using:

```objc
pod "SwiftJWT/with-ed25519"
```


## Examples

```Swift
import JWT

let jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6InBob25lIiwicGhvbmVfbnVtYmVyIjoiKzE2NTAyODU1NjAwIiwidHlwZSI6ImxhbmRsaW5lIiwiYXVkIjoiaHR0cHM6Ly9hdXRoZW50aXEuY29tIn0.CAqNpbmOA9lz9aq7Sp1NqqbdLJARmFKY3L7CKcgXLNU"

var jwt = JWT(algorithms: ["none","HS256"])
var j = jwt.loads(jwt_str, key: "secret")
let new_jwt_str = jwt.dumps("xxx")!
```

```Swift
import JWT

let jwt_ed = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiWE43VnBFWDF1Q3h4aHZ3VXVhY1lodVU5dDZ1eGdMYWhSaUxlU0VIRU5payJ9.eyJmb28iOiJiYXIifQ.a2dDcKXByKxiouOLnXUm7YUKHMGOU3yn_g91C90e8YmKjlF1_9ylAKukfMm6Y6WS3dZp2ysaglzzTnVxnRYyDQ"
let sk = "YHWUUc0P6SY46WaDdnssE8NpFsQQxJrvmdOrpU9X0wU"
let pk = "XN7VpEX1uCxxhvwUuacYhuU9t6uxgLahRiLeSEHENik"

var jwt = JWTNaCl(algorithms: ["Ed25519","none"])
jwt.loads(jwt_ed)
jwt.header["alg"] = "none"
println(jwt.dumps()!)
```

```Swift
import JWT

jwt = JWT(header: ["alg":"HS256"],
    body: [
        "sub": "1234567890",
        "name": "John Doe",
        "admin": true
    ], algorithms: nil)
println(jwt.dumps("secret")!)
```

# The Bridging Header

CommonCrypto is not a modular header in Xcode 7. This makes it very challenging to import into Swift. To work around this, the necessary header files have been copied into SwiftJWT.h, which needs to be bridged into Swift. You can do this either by using SwiftJWT as a framework, adding #import "SwiftJWT/SwiftJWT.h" to your existing bridging header, or making SwiftJWT/SwiftJWT.h your bridging header in Build Settings, "Objective-C Bridging Header."

Hopefully Apple will make CommonCrypto a modular header soon. When this happens, the bridging header will not be needed, and SwiftJWT can be a single file.

Credits for the Bridging header tip to [RNCryptor](https://github.com/RNCryptor/RNCryptor#the-bridging-header).

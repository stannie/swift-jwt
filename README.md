# swift-jwt
Swift Framework for JWT (JSON Web Token)

Created for Authentiq ID

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


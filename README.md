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

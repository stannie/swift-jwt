//
//  JWT.swift
//  
//  Stan P. van de Burgt
//  stan@vandeburgt.com
//  (c) RoundZero 2015
//  Project Authentiq

import Foundation

public class JWT {
    // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
    // base class; supports alg: none, HS256, HS384, HS512

    public var header: [String: AnyObject] = ["alg": "none", "typ": "JWT", ] {
        didSet {
            if header["alg"] as? String == nil {
                self.header["alg"] = "none"     // if not present, insert alg
            }
        }
    }
    public var body: [String: AnyObject] = [:]  // TODO: better use whitelist / allowed_algs / algoritms
    var blacklist: [String] = []                // algorithms that are deemed invalid

    public init(blacklist: [String] = []) {
        self.blacklist = blacklist
    }

    public init(header: [String: AnyObject], body: [String: AnyObject], blacklist: [String] = []) {
        self.header = header
        self.body = body
        self.blacklist = blacklist
        if header["alg"] as? String == nil {
            self.header["alg"] = "none"         // if not present, insert 'alg' (copy of didSet{} ad init does not trigger it)
        }
        if header["typ"] as? String == nil {
            self.header["typ"] = "JWT"          // if not present, insert 'typ' element
        }
    }

    public func loads(jwt: String, key: NSData?, verify: Bool = true, error: NSErrorPointer = nil) -> Bool {
        // load a JWT string into this object
        self.header = [:]
        self.body = [:]
        var sig = ""

        // split into parts, header, body, optional signature
        let parts: [String] = jwt.componentsSeparatedByString(".")
        switch parts.count {
        case 2: break
        case 3: sig = parts[2]
        default:
            if error != nil {
                error.memory = NSError(domain: "JWT", code: 1, userInfo: nil) // TODO: actual error details
            }
            return false
        }

        // decode the header (a URL-safe, base 64 encoded JSON dict) from 1st part
        let hdr_data = parts[0].base64SafeUrlDecode()
        if let dictionary = NSJSONSerialization.JSONObjectWithData(hdr_data, options: NSJSONReadingOptions(0), error: error)  as? [String: AnyObject] {
            self.header = dictionary // also sets self.alg and value for "alg" key by the didSet{} observer
        }
        else {
            return false
        }
        // check whether alg parameter is on blacklist
        // TODO: change to whitelist
        let algorithm = header["alg"] as? String
        for alg in self.blacklist {
            if alg == algorithm {
                return false
            }
        }
        // decode the body (a URL-safe base 64 encoded JSON dict) from the 2nd part
        if parts.count > 1 {
            let body_data = parts[1].base64SafeUrlDecode()
            if let dictionary = NSJSONSerialization.JSONObjectWithData(body_data, options: NSJSONReadingOptions(0), error: error)  as? [String: AnyObject] {
                self.body = dictionary
            }
        }
        else {
            return false // TODO: populate NSError
        }

        if verify {
            // verify the signature, a URL-safe base64 encoded string
            let hdr_body: String = parts[0] + "." + parts[1] // header & body of a JWT
            let data = hdr_body.dataUsingEncoding(NSUTF8StringEncoding)!
            if self.verify_signature(data, signature: sig, algorithm: algorithm!, key: key) == false {
                return false // TODO: populate NSError
            }
            // verify content fields
            if self.verify_content() == false {
                return false
            }
        }
        // TODO: do not load header & body if verification fails?
        return true
    }

    // helper function for plain strings as key
    public func loads(jwt: String, key: String, verify: Bool = true, error: NSErrorPointer = nil) -> Bool {
        let key_raw = key.dataUsingEncoding(NSUTF8StringEncoding)!
        return loads(jwt, key: key_raw, verify: verify, error: error)
    }
    
    // helper function for base64 strings as key
    public func loads(jwt: String, b64key: String, verify: Bool = true, error: NSErrorPointer = nil) -> Bool {
        let key_raw = b64key.base64SafeUrlDecode()
        return loads(jwt, key: key_raw, verify: verify, error: error)
    }

    public func dumps(key: NSData, jti_len: UInt = 16, error: NSErrorPointer = nil) -> String? {
        // TODO: some way to indicate that some fields should be generated, next to jti; e.g. nbf and iat
        var data = ""
        var payload = self.body
        // if 'jti' (the nonce) not present in body, and it is requested (jti_len > 0), set one
        if payload["jti"] as? String == nil && jti_len > 0 {
            // generate a random string (nonce) of length jti_len for body item 'jti'
            // https://developer.apple.com/library/ios/documentation/Security/Reference/RandomizationReference/index.html
            var bytes = NSMutableData(length: Int(jti_len))!
            SecRandomCopyBytes(kSecRandomDefault, jti_len, UnsafeMutablePointer<UInt8>(bytes.mutableBytes))
            payload["jti"] = bytes.base64SafeUrlEncode()
        }
        // TODO: set iat, nbf here if not set?
        if let h = NSJSONSerialization.dataWithJSONObject(self.header, options: nil, error: error) {
            data = h.base64SafeUrlEncode()
            if let b = NSJSONSerialization.dataWithJSONObject(payload, options: nil, error: error) {
                data = data + "." + b.base64SafeUrlEncode()
                let data_raw = data.dataUsingEncoding(NSUTF8StringEncoding)!
                let algorithm = header["alg"] as? String
                if let sig = self.signature(data_raw, algorithm: algorithm!, key: key) {
                    return data + "." + sig
                }
            }
        }
        return nil // TODO: populate NSError
    }

    // helper function for plain strings as key
    public func dumps(key: String, jti_len: UInt = 16, error: NSErrorPointer = nil) -> String? {
        let key_raw = key.dataUsingEncoding(NSUTF8StringEncoding)!
        return dumps(key_raw, jti_len: jti_len, error: error)
    }

    func signature(msg: NSData, algorithm: String, key: NSData) -> String? {
        // internal function to compute the signature (third) part of a JWT
        switch algorithm {
        case "none":  return ""
        case "HS256": return msg.base64digest(HMACAlgorithm.SHA256, key: key)
        case "HS384": return msg.base64digest(HMACAlgorithm.SHA384, key: key)
        case "HS512": return msg.base64digest(HMACAlgorithm.SHA512, key: key)
        case "RS256": return msg.rsa_signature(HMACAlgorithm.SHA256, key: key)
        case "RS384": return msg.rsa_signature(HMACAlgorithm.SHA384, key: key)
        case "RS512": return msg.rsa_signature(HMACAlgorithm.SHA512, key: key)
        // TODO: support for RSASSA-PSS algorithms: "PS256", "PS384", and "PS512"
        default:      return nil
        }
    }

    func verify_signature(msg: NSData, signature: String, algorithm: String, key: NSData? = nil) -> Bool {
        // internal function to verify the signature (third) part of a JWT
        if key == nil && algorithm != "none" {
            return false
        }
        switch algorithm {
        case "none":  return signature == "" // if "none" then the signature shall be empty
        case "HS256": return msg.base64digest(HMACAlgorithm.SHA256, key: key!) == signature
        case "HS384": return msg.base64digest(HMACAlgorithm.SHA384, key: key!) == signature
        case "HS512": return msg.base64digest(HMACAlgorithm.SHA512, key: key!) == signature
        case "RS256": return msg.rsa_verify(HMACAlgorithm.SHA256, signature: signature, key: key!)
        case "RS384": return msg.rsa_verify(HMACAlgorithm.SHA384, signature: signature, key: key!)
        case "RS512": return msg.rsa_verify(HMACAlgorithm.SHA512, signature: signature, key: key!)
        // TODO: support for RSASSA-PSS algorithms: "PS256", "PS384", and "PS512"
        default:      return false
        }
    }

    // TODO: some way to enforce that e.g. iat and nbf are present
    // TODO: verification of iss and aud when given in loads()
    func verify_content() -> Bool {
        // internal function to verify the content (header and body) parts of a JWT
        let date = NSDate()
        let now = UInt(date.timeIntervalSince1970)

        if let typ = self.header["typ"] as? String {
            if typ != "JWT" { return false } // 'typ' shall be 'JWT'
        }
        else {
            return false // 'typ' shall be present
        }
        if let exp = self.body["exp"] as? UInt {
            if now > exp { return false }
        }
        if let nbf = self.body["nbf"] as? UInt {
            if now < nbf { return false }
        }
        if let iat = self.body["iat"] as? UInt {
            if now < iat { return false }
        }
        return true
    }
}

// MARK: - NaCl signatures
// subclass with additional sign/verify for "Ed25519" signatures
// TODO: move following class and nacl_* extentions to NSData to JWTNaCl.swift ?

public class JWTNaCl: JWT {

    override func signature(msg: NSData, algorithm: String, key: NSData) -> String? {
        if algorithm == "Ed25519" {
            return msg.nacl_signature(key)
        }
        else {
            return super.signature(msg, algorithm: algorithm, key: key)
        }
    }

    override func verify_signature(msg: NSData, signature: String, algorithm: String, key: NSData? = nil) -> Bool {
        if algorithm == "Ed25519" {
            if key == nil {
                // use the "kid" field as base64 key string as key if no key provided.
                if let kid = header["kid"] as? String {
                    return msg.nacl_verify(signature, key: kid.base64SafeUrlDecode())
                }
            }
            else {
                return msg.nacl_verify(signature, key: key!)
            }
        }
        else {
            return super.verify_signature(msg, signature: signature, algorithm: algorithm, key: key)
        }
        return false
    }

    override func verify_content() -> Bool {
        if let kid = self.header["kid"] as? String {
            let pk = kid.base64SafeUrlDecode(nil)
            if pk == nil || pk!.length != 32 {
                return false
            }
        }
        else {
            return false // kid is not optional when using NaCl
        }
        if let sub = self.body["sub"] as? String {
            let id = sub.base64SafeUrlDecode(nil)
            if id == nil || id!.length != 32 {
                return false
            }
        }
        return super.verify_content() // run the parent tests too
    }
}

// MARK: - base64 extensions

extension String {
    func base64SafeUrlDecode() -> NSData { // ! ?
        return self.base64SafeUrlDecode(nil)
    }
    
    func base64SafeUrlDecode(options: NSDataBase64DecodingOptions) -> NSData! {
        var s: String = self;
        
        s = s.stringByReplacingOccurrencesOfString("-", withString: "+") // 62nd char of encoding
        s = s.stringByReplacingOccurrencesOfString("_", withString: "/") // 63rd char of encoding
        
        switch (countElements(s) % 4) {     // Pad with trailing '='s
        case 0: break; // No pad chars in this case
        case 2: s += "=="; break; // Two pad chars
        case 3: s += "="; break; // One pad char
        default: return nil
        }
        
        return NSData(base64EncodedString: s, options: options)!
    }
}

extension NSData {
    func base64SafeUrlEncode() -> String {
        return self.base64SafeUrlEncode(nil)
    }
    
    func base64SafeUrlEncode(options: NSDataBase64EncodingOptions) -> String {
        var s: String = self.base64EncodedStringWithOptions(options)
        if let idx = find(s, "=") {
            s = s.substringToIndex(idx) // remove trailing '='s
        }
        s = s.stringByReplacingOccurrencesOfString("/", withString: "_") // 63rd char of encoding
        s = s.stringByReplacingOccurrencesOfString("+", withString: "-") // 62nd char of encoding
        return s
    }
}

// MARK: - HMACAlgorithm
// See http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework (answer by stephencelis) on how to import

import CommonCrypto

// See: http://stackoverflow.com/questions/24099520/commonhmac-in-swift (answer by hdost) on HMAC signing.
// note that MD5, SHA1 and SHA224 are not used as JWT algorithms

enum HMACAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    func toCCEnum() -> CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:
            result = kCCHmacAlgMD5
        case .SHA1:
            result = kCCHmacAlgSHA1
        case .SHA224:
            result = kCCHmacAlgSHA224
        case .SHA256:
            result = kCCHmacAlgSHA256
        case .SHA384:
            result = kCCHmacAlgSHA384
        case .SHA512:
            result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
    
    func digestLength() -> Int {
        var result: CInt = 0
        switch self {
        case .MD5:
            result = CC_MD5_DIGEST_LENGTH
        case .SHA1:
            result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:
            result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:
            result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:
            result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:
            result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}

// See http://stackoverflow.com/questions/21724337/signing-and-verifying-on-ios-using-rsa on RSA signing


import Sodium
// swift wrapper of LibSodium, a NaCl implementation https://github.com/jedisct1/swift-sodium
// git checkout 176033d7c1cbc4dfe4bed648aa230c9e14ab9426 # for Swift 1.1, as latest is 1.2

extension NSData {

    // Inspired by: http://stackoverflow.com/questions/24099520/commonhmac-in-swift (answer by hdost)
    func base64digest(algorithm: HMACAlgorithm, key: NSData) -> String! {
        let data = self.bytes
        let dataLen = UInt(self.length)
        let digestLen = algorithm.digestLength()
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        let keyData = key.bytes
        let keyLen = UInt(key.length)
        
        CCHmac(algorithm.toCCEnum(), keyData, keyLen, data, dataLen, result)
        let hdata = NSData(bytes: result, length: digestLen)
        result.destroy()
        
        return hdata.base64SafeUrlEncode()
    }

    func nacl_signature(key: NSData) -> String! {
        let sodium = Sodium()
        if let sig = sodium?.sign.signature(self, secretKey: key) {
            return sig.base64SafeUrlEncode()
        }
        return nil
    }
    func nacl_verify(signature: String, key: NSData) -> Bool {
        if let sodium = Sodium() {
            let sig_raw = signature.base64SafeUrlDecode()
            return sodium.sign.verify(self, publicKey: key, signature: sig_raw)
        }
        return false
    }

    // TODO: finalize the next 2 functions to implement RSnnn algorithms, for nnn = 224 or 256 or 384 or 512
    // based on http://stackoverflow.com/questions/21724337/signing-and-verifying-on-ios-using-rsa

    // TODO: use an algorithm parameter
    func rsa_signature(algorithm: HMACAlgorithm, key: NSData) -> String! {
        // TODO: how to get to the SecKey part / version of the private key, if given as NSData
        let privkey: SecKey? = nil
        let msg = UnsafePointer<UInt8>(self.bytes)
        let msglen = UInt(self.length)

        let sha_buf = UnsafeMutablePointer<UInt8>.alloc(Int(CC_SHA256_DIGEST_LENGTH)) // or 224 or 384 or 512
        let sha_result = CC_SHA256(msg, CC_LONG(msglen), sha_buf) // or 224 or 384 or 512

        var sig = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))! // or 224 or 384 or 512
        var sigbuf = UnsafeMutablePointer<UInt8>(sig.mutableBytes) // or UnsafeMutablePointer<UInt8>.alloc(Int(CC_SHA256_DIGEST_LENGTH)) ?
        let siglen = UnsafeMutablePointer<UInt>.alloc(1) // correct? and initialize to CC_SHA256_DIGEST_LENGTH ?

        // TODO: fix error in next line, call to SecKeyRawSign
        //let status = SecKeyRawSign(key: privkey!, padding: kSecPaddingPKCS1SHA256, dataToSign: msg, dataToSignLen: msglen, sig: sigbuf, sigLen: siglen)

        //OSStatus SecKeyRawSign(
        //    SecKeyRef           privKey,
        //    SecPadding          padding,
        //    const uint8_t       *dataToSign,
        //    size_t              dataToSignLen,
        //    uint8_t             *sig,
        //    size_t              *sigLen)

        return sig.base64SafeUrlEncode()
    }

    func rsa_verify(algorithm: HMACAlgorithm, signature: String, key: NSData) -> Bool {
        let pubkey: SecKey? = nil
        let msg = UnsafePointer<UInt8>(self.bytes)
        let msglen = UInt(self.length)

        let sha_buf = UnsafeMutablePointer<UInt8>.alloc(Int(CC_SHA256_DIGEST_LENGTH))
        let sha_result = CC_SHA256(msg, CC_LONG(msglen), sha_buf)

        var sig = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))!
        let sig_raw = signature.base64SafeUrlDecode()
        var sigbuf = UnsafeMutablePointer<UInt8>(sig_raw.bytes) // or UnsafeMutablePointer<UInt8>.alloc(Int(CC_SHA256_DIGEST_LENGTH)) ?
        let siglen = UInt(sig_raw.length)

        // TODO: fix error in next line, call to SecKeyRawSign
        // let status = SecKeyRawVerify(key: pubkey!, padding: kSecPaddingPKCS1SHA256, signedData: msg, signedDataLen: msglen, sig: sigbuf, sigLen: siglen)
        // OSStatus SecKeyRawVerify(key: SecKey!, padding: SecPadding, signedData: UnsafePointer<UInt8>, signedDataLen: UInt, sig: UnsafePointer<UInt8>, sigLen: UInt)

        return false // status == errSecSuccess
    }
}

// END

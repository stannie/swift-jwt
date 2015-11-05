//
//  JWTNaCl.swift
//
//  Stan P. van de Burgt
//  stan@vandeburgt.com
//  (c) RoundZero 2015
//  Project Authentiq

// MARK: - NaCl signatures
// subclass with additional sign/verify for "Ed25519" signatures

public enum JWTNaClError: ErrorType {
    case InvalidKid
    case InvalidSub
}

public class JWTNaCl: JWT {
    
    public func _kid(key: NSData) -> String {
        return key.base64SafeUrlEncode()
    }
    
    override func implemented(algorithm: String?) -> Bool {
        let algorithms = ["Ed25519"]
        for alg in algorithms {
            if alg == algorithm {
                return true
            }
        }
        return super.implemented(algorithm) // not implemented here, so try parent
    }
    
    override func signature(msg: NSData, algorithm: String, key: NSData?) -> String? {
        if algorithm == "Ed25519" {
            return msg.nacl_signature(key!) // will crash on nil key
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
    
    override func verify_content() throws {
        
        // kid is not optional when using NaCl
        // TIP: use guard statement
        guard let kid = self.header["kid"] as? String
            where kid.base64SafeUrlDecode([]).length == 32 else {
                
                throw JWTNaClError.InvalidKid
        }
        
        if let sub = self.body["sub"] as? String {
            let id = sub.base64SafeUrlDecode([])
            if id.length != 32 {
                throw JWTNaClError.InvalidSub
            }
        }
        
        try super.verify_content() // run the parent tests too
    }
}

// MARK: - HMACAlgorithm
// See http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework (answer by stephencelis) on how to import

// import CommonCrypto

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


import Sodium   // swift wrapper of LibSodium, a NaCl implementation https://github.com/jedisct1/swift-sodium

extension NSData {
    
    func base64digest(algorithm: HMACAlgorithm, key: NSData) -> String! {
        let digestLen = algorithm.digestLength()
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        
        // Inspired by: http://stackoverflow.com/questions/24099520/commonhmac-in-swift (answer by hdost)
        // CCHmac(algorithm: algorithm.toCCEnum(), key: keyData, keyLength: keyLen, data: data, dataLength: dataLen, macOut: result)
        CCHmac(algorithm.toCCEnum(), key.bytes, key.length, self.bytes, self.length, result)
        let hdata = NSData(bytes: result, length: digestLen)
        result.destroy()
        
        return hdata.base64SafeUrlEncode()
    }
    
    func nacl_signature(key: NSData) -> String! {
        // key is privkey
        let sodium = Sodium()
        if let sig = sodium?.sign.signature(self, secretKey: key) {
            return sig.base64SafeUrlEncode()
        }
        return nil
    }
    func nacl_verify(signature: String, key: NSData) -> Bool {
        // key is pubkey
        if let sodium = Sodium() {
            let sig_raw = signature.base64SafeUrlDecode()
            return sodium.sign.verify(self, publicKey: key, signature: sig_raw)
        }
        return false
    }
    
    // based on http://stackoverflow.com/questions/21724337/signing-and-verifying-on-ios-using-rsa
    
    func rsa_signature(algorithm: HMACAlgorithm, key: NSData) -> String? {
        // key is privkey, in raw format
        let privkey: SecKey? = nil // TODO: get the SecKey format of the (private) key
        let msgbytes = UnsafePointer<UInt8>(self.bytes)
        let msglen = CC_LONG(self.length)
        let digestlen = algorithm.digestLength()
        let digest = NSMutableData(length: digestlen)!
        let digestbytes = UnsafeMutablePointer<UInt8>(digest.mutableBytes)
        var padding: SecPadding
        
        switch algorithm {
        case .SHA256: // TODO: change to HS256, ... ?
            CC_SHA256(msgbytes, msglen, digestbytes) // TODO: test on nil return?
            padding = SecPadding.PKCS1SHA256
        case .SHA384:
            CC_SHA256(msgbytes, msglen, digestbytes)
            padding = SecPadding.PKCS1SHA384
        case .SHA512:
            CC_SHA256(msgbytes, msglen, digestbytes)
            padding = SecPadding.PKCS1SHA512
        default:
            return nil
        }
        
        let sig = NSMutableData(length: digestlen)!
        let sigbytes = UnsafeMutablePointer<UInt8>(sig.mutableBytes) // or UnsafeMutablePointer<UInt8>.alloc(Int(digestLen)) ?
        var siglen: Int = digestlen
        
        // OSStatus SecKeyRawSign(key: SecKey!, padding: SecPadding, dataToSign: UnsafePointer<UInt8>, dataToSignLen: Int, sig: UnsafeMutablePointer<UInt8>, sigLen: UnsafeMutablePointer<Int>)
        let status = SecKeyRawSign(privkey!, padding, digestbytes, digestlen, sigbytes, &siglen)
        if status == errSecSuccess {
            // use siglen in/out parameter to set the actual lenght of sig
            sig.length = siglen
            return sig.base64SafeUrlEncode()
        }
        return nil
    }
    
    func rsa_verify(algorithm: HMACAlgorithm, signature: String, key: NSData) -> Bool {
        // key is pubkey, in raw format
        let pubkey: SecKey? = nil /// TODO: get the SecKey format of the (public) key
        let msgbytes = UnsafePointer<UInt8>(self.bytes)
        let msglen = CC_LONG(self.length)
        let digestlen = algorithm.digestLength()
        let digest = NSMutableData(length: digestlen)!
        let digestbytes = UnsafeMutablePointer<UInt8>(digest.mutableBytes)
        var padding: SecPadding
        
        switch algorithm {
        case .SHA256: // TODO: change to HS256, ...
            CC_SHA256(msgbytes, msglen, digestbytes) // TODO: test on nil return?
            padding = SecPadding.PKCS1SHA256
        case .SHA384:
            CC_SHA256(msgbytes, msglen, digestbytes)
            padding = SecPadding.PKCS1SHA384
        case .SHA512:
            CC_SHA256(msgbytes, msglen, digestbytes)
            padding = SecPadding.PKCS1SHA512
        default:
            return false
        }
        
        let sig_raw = signature.dataUsingEncoding(NSUTF8StringEncoding)!
        let sigbytes = UnsafePointer<UInt8>(sig_raw.bytes)
        let siglen = sig_raw.length
        
        // OSStatus SecKeyRawVerify(key: SecKey!, padding: SecPadding, signedData: UnsafePointer<UInt8>, signedDataLen: Int, sig: UnsafePointer<UInt8>, sigLen: Int)
        let status = SecKeyRawVerify(pubkey!, padding, digestbytes, digestlen, sigbytes, siglen)
        
        return status == errSecSuccess
    }
}

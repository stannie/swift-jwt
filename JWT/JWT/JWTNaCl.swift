//
//  JWTNaCl.swift
//
//  Stan P. van de Burgt
//  stan@vandeburgt.com
//  (c) RoundZero 2015
//  Project Authentiq

import Sodium
import CommonCrypto

// MARK: - NaCl signatures
// subclass with additional sign/verify for "Ed25519" signatures

public enum JWTNaClError: Error {
    case invalidKid
    case invalidSub
}

public class JWTNaCl: JWT {
    
    public func _kid(_ key: Data) -> String {
        return key.base64SafeUrlEncode()
    }
    
    override func implemented(_ algorithm: String?) -> Bool {
        let algorithms = ["Ed25519"]
        for alg in algorithms {
            if alg == algorithm {
                return true
            }
        }
        return super.implemented(algorithm) // not implemented here, so try parent
    }
    
    override func signature(_ msg: Data, algorithm: String, key: Data?) -> String? {
        if algorithm == "Ed25519" {
            return msg.nacl_signature(key!) // will crash on nil key
        }
        else {
            return super.signature(msg, algorithm: algorithm, key: key)
        }
    }
    
    override func verify_signature(_ msg: Data, signature: String, algorithm: String, key: Data? = nil) -> Bool {
        if algorithm == "Ed25519" {
            if key == nil {
                // use the "kid" field as base64 key string as key if no key provided.
                if let kid = header["kid"] as? String,
                    let b64key = kid.base64SafeUrlDecode() {
                    return msg.nacl_verify(signature, key: b64key)
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
    
    override open func verify_content() throws {
        
        // kid is not optional when using NaCl
        // TIP: use guard statement
        guard let kid = self.header["kid"] as? String,
            let kidData = kid.base64SafeUrlDecode(),
            kidData.count == 32
        else {
            throw JWTNaClError.invalidKid
        }
        
        if let sub = self.body["sub"] as? String,
            let id = sub.base64SafeUrlDecode(),
            id.count != 32
        {
            throw JWTNaClError.invalidSub
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
    case md5, sha1, sha224, sha256, sha384, sha512
    
    func toCCEnum() -> CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .md5:
            result = kCCHmacAlgMD5
        case .sha1:
            result = kCCHmacAlgSHA1
        case .sha224:
            result = kCCHmacAlgSHA224
        case .sha256:
            result = kCCHmacAlgSHA256
        case .sha384:
            result = kCCHmacAlgSHA384
        case .sha512:
            result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
    
    func digestLength() -> Int {
        var result: CInt = 0
        switch self {
        case .md5:
            result = CC_MD5_DIGEST_LENGTH
        case .sha1:
            result = CC_SHA1_DIGEST_LENGTH
        case .sha224:
            result = CC_SHA224_DIGEST_LENGTH
        case .sha256:
            result = CC_SHA256_DIGEST_LENGTH
        case .sha384:
            result = CC_SHA384_DIGEST_LENGTH
        case .sha512:
            result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}

// See http://stackoverflow.com/questions/21724337/signing-and-verifying-on-ios-using-rsa on RSA signing
extension Data {
    func base64digest(_ algorithm: HMACAlgorithm, key: Data) -> String! {
        let digestLen = algorithm.digestLength()
        
        var digest = Data(count: digestLen)
        _ = digest.withUnsafeMutableBytes { mutableBytes in
            key.withUnsafeBytes { keybytes in
                self.withUnsafeBytes { bytes in

                    // Inspired by: http://stackoverflow.com/questions/24099520/commonhmac-in-swift (answer by hdost)
                    // CCHmac(algorithm: algorithm.toCCEnum(), key: keyData, keyLength: keyLen, data: data, dataLength: dataLen, macOut: result)
                    CCHmac(algorithm.toCCEnum(), keybytes, key.count, bytes, self.count, mutableBytes)
                }
            }
        }

        // TODO: catch errors and throw?
        
        return digest.base64SafeUrlEncode()
    }
    
    func nacl_signature(_ key: Data) -> String! {
        // key is privkey
        
        let sodium = Sodium()
        if let sig = sodium.sign.signature(message: Bytes(self),
                                            secretKey: Bytes(key))
        {
            return Data(bytes: sig).base64SafeUrlEncode()
        }
        return nil
    }

    func nacl_verify(_ signature: String, key: Data) -> Bool {
        // key is pubkey
        
        let sodium = Sodium()
        if let sig_raw = signature.base64SafeUrlDecode() {
            return sodium.sign.verify(message: Bytes(self),
                                      publicKey: Bytes(key),
                                      signature: Bytes(sig_raw))
        }
        return false
    }
    
    // based on http://stackoverflow.com/questions/21724337/signing-and-verifying-on-ios-using-rsa
    
    func rsa_signature(_ algorithm: HMACAlgorithm, key: Data) -> String? {
        // key is privkey, in raw format
        let privkey: SecKey? = nil // TODO: get the SecKey format of the (private) key
        let msglen = CC_LONG(self.count)
        let digestlen = algorithm.digestLength()
        
        var digest = Data(count: digestlen)
        _ = digest.withUnsafeMutableBytes { mutableBytes in
            self.withUnsafeBytes { bytes in
                // TODO: test on nil return?
                CC_SHA256(bytes, msglen, mutableBytes)
            }
        }
        
        var padding: SecPadding
        
        switch algorithm {
        case .sha256: // TODO: change to HS256, ... ?
            padding = SecPadding.PKCS1SHA256
        case .sha384:
            padding = SecPadding.PKCS1SHA384
        case .sha512:
            padding = SecPadding.PKCS1SHA512
        default:
            return nil
        }

        var sig = Data(count: digestlen)
        var siglen: Int = digestlen
        let status = sig.withUnsafeMutableBytes { mutableBytes in
            digest.withUnsafeBytes { digestbytes in
                SecKeyRawSign(privkey!, padding, digestbytes, digestlen, mutableBytes, &siglen)
            }
        }
        
        // OSStatus SecKeyRawSign(key: SecKey!, padding: SecPadding, dataToSign: UnsafePointer<UInt8>, dataToSignLen: Int, sig: UnsafeMutablePointer<UInt8>, sigLen: UnsafeMutablePointer<Int>)
        if status == errSecSuccess {
            // use siglen in/out parameter to set the actual lenght of sig
            sig.count = siglen
            return (sig as Data).base64SafeUrlEncode()
        }
        return nil
    }
    
    func rsa_verify(_ algorithm: HMACAlgorithm, signature: String, key: Data) -> Bool {
        // key is pubkey, in raw format
        let pubkey: SecKey? = nil /// TODO: get the SecKey format of the (public) key
        let msglen = CC_LONG(self.count)
        let digestlen = algorithm.digestLength()
        
        var digest = Data(count: digestlen)
        _ = digest.withUnsafeMutableBytes { mutableBytes in
            self.withUnsafeBytes { bytes in
                // TODO: test on nil return?
                CC_SHA256(bytes, msglen, mutableBytes)
            }
        }
        
        var padding: SecPadding
        
        switch algorithm {
        case .sha256: // TODO: change to HS256, ... ?
            padding = SecPadding.PKCS1SHA256
        case .sha384:
            padding = SecPadding.PKCS1SHA384
        case .sha512:
            padding = SecPadding.PKCS1SHA512
        default:
            return false
        }
        
        let sig_raw = signature.data(using: String.Encoding.utf8)!
        let sigbytes = (sig_raw as NSData).bytes.bindMemory(to: UInt8.self, capacity: sig_raw.count)
        let siglen = sig_raw.count
        
        // OSStatus SecKeyRawVerify(key: SecKey!, padding: SecPadding, signedData: UnsafePointer<UInt8>, signedDataLen: Int, sig: UnsafePointer<UInt8>, sigLen: Int)
        let status = digest.withUnsafeBytes { digestbytes in
            SecKeyRawVerify(pubkey!, padding, digestbytes, digestlen, sigbytes, siglen)
        }
        
        return status == errSecSuccess
    }
}

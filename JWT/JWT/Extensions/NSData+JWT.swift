//
//  NSData+JWT.swift
//  SwiftJWT
//
//  Created by Chris Ziogas on 05/11/15.
//  Copyright © 2015 RoundZero bv. All rights reserved.
//

import Foundation

extension NSData {
    // MARK: - base64 extensions
    func base64SafeUrlEncode() -> String {
        return self.base64SafeUrlEncode([])
    }
    
    func base64SafeUrlEncode(options: NSDataBase64EncodingOptions) -> String {
        // regular base64 encoding
        var s: String = self.base64EncodedStringWithOptions(options)
        
        // s = s.substringToIndex(s.endIndex.predecessor()) // remove last char
        s = s.stringByReplacingOccurrencesOfString("=", withString: "") // Remove any trailing '='s
        s = s.stringByReplacingOccurrencesOfString("+", withString: "-") // 62nd char of encoding
        s = s.stringByReplacingOccurrencesOfString("/", withString: "_") // 63rd char of encoding
        
        return s;
    }
}
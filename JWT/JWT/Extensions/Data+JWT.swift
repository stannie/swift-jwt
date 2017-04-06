//
//  NSData+JWT.swift
//  SwiftJWT
//
//  Created by Chris Ziogas on 05/11/15.
//  Copyright © 2015 RoundZero bv. All rights reserved.
//

import Foundation

extension Data {
    // MARK: - base64 extensions
    func base64SafeUrlEncode(_ options: Data.Base64EncodingOptions = []) -> String {
        // regular base64 encoding
        var s = self.base64EncodedString(options: options)
        
        // s = s.substringToIndex(s.endIndex.predecessor()) // remove last char
        s = s.replacingOccurrences(of: "=", with: "") // Remove any trailing '='s
        s = s.replacingOccurrences(of: "+", with: "-") // 62nd char of encoding
        s = s.replacingOccurrences(of: "/", with: "_") // 63rd char of encoding
        
        return s
    }
}

//
//  Sha256+CC.swift
//
//  Copyright 2018 Warner Zee
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#if os(OSX)

import Cocoa

public struct Sha256_CC {
  
  //// 256-bit message digest.
  public var digest: Data?

  /// Produce a SHA-256 message digest from a data source.
  ///
  /// - Parameter data: Data source to be hashed.
  public init(data: Data) {
    let transform = SecDigestTransformCreate(kSecDigestSHA2, 256, nil)
    SecTransformSetAttribute(transform, kSecTransformInputAttributeName, data as CFTypeRef, nil)
    digest = SecTransformExecute(transform, nil) as? Data
  }
  
  /// Produce a SHA-256 message digest from a resource on a remote server or local file.
  ///
  /// Returns `nil` if an input stream cannot be created from the url.
  ///
  /// - Parameter url: URL for resource to be hashed.
  public init?(url: URL) {
    guard let data = try? Data(contentsOf: url) else { return nil }
    self.init(data: data)
  }
  
  /// Produce a SHA-256 message digest from a string
  ///
  /// Returns `nil` if the string cannot be encoded to a byte buffer using `utf8`.
  ///
  /// - Parameter url: String to be hashed.
  public init?(string: String) {
    guard let data = string.data(using: .utf8) else { return nil }
    self.init(data: data)
  }
  
}

#else
  
import Foundation
  
public struct SHA256_CC {
    
}
  
#endif

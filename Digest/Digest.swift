//
//  Digest.swift
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

import Foundation

public struct Digest {
  
  /// Bundle Id for this framework.
  public static let bundleId = "com.wyz.Digest"
  
  /// Name for this framework.
  public static var name: String {
    let info = Bundle(identifier: bundleId)!.infoDictionary!
    let name = info["CFBundleName"] as! String
    let version = info["CFBundleShortVersionString"] as! String
    return "\(name) v\(version)"
  }
  
}

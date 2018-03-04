//
//  DigestTests.swift
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

import XCTest
import Digest

class DigestTests: XCTestCase {
  
  override func setUp() {
    super.setUp()
  }
  
  override func tearDown() {
    super.tearDown()
  }
  
  func testSha256_Nist() {
    // first 512
    XCTAssertEqual(Sha256_Nist(string: "")?.digest?.hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    XCTAssertEqual(Sha256_Nist(string: " ")?.digest?.hex, "36a9e7f1c95b82ffb99743e0c5c4ce95d83c9a430aac59f84ef3cbfab6145068")
    XCTAssertEqual(Sha256_Nist(string: "1")?.digest?.hex, "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b")
    XCTAssertEqual(Sha256_Nist(string: "0123456789012345678901234567890123456789012345678901234")?.digest?.hex, "f34d5a0f80c0cbf84c8c0b90218c22637abd199965249da736a20143c8c9c9d9")
    
    // second 512
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345")?.digest?.hex, "83aa034bda83e458a0dc9cbce0d4e354716aa0ff770ed37ac0ed2b292052e4af")
    XCTAssertEqual(Sha256_Nist(string: "012345678901234567890123456789012345678901234567890123456")?.digest?.hex, "2f599f9dd7fac80e26892a008adcf28c0c9aaa11cf3df4ceacd07d0f1aef4c76")
    XCTAssertEqual(Sha256_Nist(string: "0123456789012345678901234567890123456789012345678901234567")?.digest?.hex, "092b99979723989faa6f2a155a1226745a10cd3b07a57a49d0679d8711720bc0")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678")?.digest?.hex, "1d4e6890758b06721d555fa20df73912972a3e63cbc8921f5caa30e72c835736")
    XCTAssertEqual(Sha256_Nist(string: "012345678901234567890123456789012345678901234567890123456789")?.digest?.hex, "5e43c8704ac81f33d701c1ace046ba9f257062b4d17e78f3254cbf243177e4f2")
    XCTAssertEqual(Sha256_Nist(string: "0123456789012345678901234567890123456789012345678901234567890")?.digest?.hex, "4479dab395552c7a01190926e54af267c657d64e36bb7233ad36c22c2823aad8")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678901")?.digest?.hex, "4c1ece5b167ee2bab7c76a3afe6c287d8e901362c676a20b5ae5450faa37382d")
    XCTAssertEqual(Sha256_Nist(string: "012345678901234567890123456789012345678901234567890123456789012")?.digest?.hex, "074f6e9ac301d5d1b6df6f1dfb8c6f89c187ea945d352ce6a29279a9c630680b")
    XCTAssertEqual(Sha256_Nist(string: "0123456789012345678901234567890123456789012345678901234567890123")?.digest?.hex, "9674d9e078535b7cec43284387a6ee39956188e735a85452b0050b55341cda56")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678901234")?.digest?.hex, "52774b57c10e45040a61c14d35c1c8ebefe880082313aa0a21ebb077734cd067")
    XCTAssertEqual(Sha256_Nist(string: "012345678901234567890123456789012345678901234567890123456789012345")?.digest?.hex, "82db6bb07e2233c096811f645f2b5549ffb21b98eca1e9aca25706eee4c239ef")
    XCTAssertEqual(Sha256_Nist(string: "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567")?.digest?.hex, "eef0ffdb463a4094e29a52d0aa4c2177eb6cb7dbf194a5e1c4a17f7131bc1c59")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678")?.digest?.hex, "d0cb70d05ff14123f114c0cca360c62077379cf1ac90e1bfafa9e9e4d827596a")
    
    // third 512
    XCTAssertEqual(Sha256_Nist(string: "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789")?.digest?.hex, "08642f0525963875af954100280fe3009293fa7e19c273444f31464c9b089243")
    XCTAssertEqual(Sha256_Nist(string: "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890")?.digest?.hex, "86e1b6d6d9e22338af4ad4c77f402edb907f05987212b25605462479ccbc8b39")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901")?.digest?.hex, "bf1b9c1095200f8f3da3b7d3c5e787c29a7e157214df09c310287dd3c5707690")
    XCTAssertEqual(Sha256_Nist(string: "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012")?.digest?.hex, "fadbd3b70e36570270f995ef2e0691d161b4d89634a7aba300f29194b49fd043")
    XCTAssertEqual(Sha256_Nist(string: "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123")?.digest?.hex, "b00cc444ea484484952ca3f8b5e925e0a11c1f173c41fdb40d11d4d61a8b12f5")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234")?.digest?.hex, "16b2f17b9e6d6b958f4ae1b854fcbfa46dfa805790a2b431b7a48a9689bcb617")
    XCTAssertEqual(Sha256_Nist(string: "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345")?.digest?.hex, "308599eb0c3be780b974d8cffc3c7fa8722b147e812408cdb05bf403f125a0e4")
    XCTAssertEqual(Sha256_Nist(string: "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456")?.digest?.hex, "8e1814fdcfd56f26b96bcdba97754ab886dcb95373419b94a341a17d2634775e")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567")?.digest?.hex, "916e19992e7f9b1e8d9267c3324616dac8f4199419c6e4ebf68fda985f4b64ea")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567")?.digest?.hex, "916e19992e7f9b1e8d9267c3324616dac8f4199419c6e4ebf68fda985f4b64ea")
    XCTAssertEqual(Sha256_Nist(string: "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567")?.digest?.hex, "916e19992e7f9b1e8d9267c3324616dac8f4199419c6e4ebf68fda985f4b64ea")
  }

}

//
//  ViewController.swift
//  sekey
//
//  Created by David Wagner on 20/06/2018.
//  Copyright © 2018 David Wagner. All rights reserved.
//

import UIKit

extension Data {
    func toHex() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

class ViewController: UIViewController {

    private static let keyTag = "com.noiseandheat.experiment.sekey.key"
    private static let keyType = kSecAttrKeyTypeECSECPrimeRandom
    private static let encryptionAlgorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM


    @IBOutlet var inputText: UITextView!
    @IBOutlet var encryptedText: UITextView!
    @IBOutlet var outputText: UITextView!
    
    var privateKey: SecKey!
    lazy var publicKey: SecKey = {
        guard let key = SecKeyCopyPublicKey(privateKey) else {
            fatalError("Could not copy public key")
        }
        return key
    }()
    
    var encrypted:Data?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        if let existingKey = fetchKey() {
            print("Using existing key")
            privateKey = existingKey
        } else {
            print("Generating new key")
            do {
                privateKey = try createKeyPair()
            } catch {
                fatalError("Aww. \(error)")
            }
        }
        
        outputInterestingThings()
    }
    
    @IBAction func handleEncrypt(_ sender: UIButton) {
        do {
            encrypted = try encrypt(inputText.text)
            encryptedText.text = encrypted?.toHex()
        } catch {
            encryptedText.text = "Encryption failed: \(error)"
        }
    }
    
    @IBAction func handleDecrypt(_ sender: UIButton) {
        guard let encryptedData = encrypted else {
            outputText.text = "Encrypt something first!"
            return
        }
        
        do {
            outputText.text = try decrypt(encryptedData)
        } catch {
            outputText.text = "Decryption failed: \(error)"
        }
    }
    
}

extension ViewController {
    func outputInterestingThings() {
        print("Public key supports encryption: \(SecKeyIsAlgorithmSupported(publicKey, .encrypt, ViewController.encryptionAlgorithm))")
        print("Private key supports decryption: \(SecKeyIsAlgorithmSupported(privateKey, .decrypt, ViewController.encryptionAlgorithm))")
        print("Private key block size: \(SecKeyGetBlockSize(privateKey)) bytes")
        
    }
}

extension ViewController {
    func encrypt(_ message: String) throws -> Data {
        var error: Unmanaged<CFError>?
        let plainText = message.data(using: .utf8)!
        guard let cipherText = SecKeyCreateEncryptedData(publicKey,
                                                         ViewController.encryptionAlgorithm,
                                                         plainText as CFData,
                                                         &error) as Data? else {
                                                            throw error!.takeRetainedValue() as Error
        }
        return cipherText
    }
    
    func decrypt(_ encryptedData: Data) throws -> String {
        var error: Unmanaged<CFError>?
        guard let clearText = SecKeyCreateDecryptedData(privateKey,
                                                        ViewController.encryptionAlgorithm,
                                                        encryptedData as CFData,
                                                        &error) as Data? else {
                                                            throw error!.takeRetainedValue() as Error
        }
        return String(data: clearText, encoding: .utf8)!
    }
}

extension ViewController {
    func createAccessControl() -> SecAccessControl? {
        return SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil)
    }
    
    func createAttributeDictionary() -> [String:Any] {
        guard let access = createAccessControl() else { fatalError("Aw, failed to create access controls") }
        let attributes: [String:Any] =  [
            kSecAttrKeyType as String: ViewController.keyType,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: ViewController.keyTag,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        return attributes
    }
    
    func createKeyPair() throws -> SecKey {
        let attributes = createAttributeDictionary()
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }
}

extension ViewController {
    func fetchKey() -> SecKey? {
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: ViewController.keyTag,
                                    kSecAttrKeyType as String: ViewController.keyType,
                                    kSecReturnRef as String: true]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        return (item as! SecKey)
    }
}


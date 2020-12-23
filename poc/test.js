// NodeJS client for testing purposes
const _sodium = require('libsodium-wrappers');

(async() => {
    await _sodium.ready;
    const sodium = _sodium;

    const KEY_BYTES = sodium.crypto_secretbox_KEYBYTES;
    const NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES;

    // Generate Alice Secret Key
    let aliceSecretKey = sodium.randombytes_buf(32);
    console.log('Alice Secret Key: ' + Buffer.from(aliceSecretKey).toString('base64'));

    // Generate Alice Key Pair
    let aliceKeyPair = sodium.crypto_box_keypair();
    console.log('Alice Public Key: ' + Buffer.from(aliceKeyPair.publicKey).toString('base64'));
    console.log('Alice Private Key: ' + Buffer.from(aliceKeyPair.privateKey).toString('base64'));

    // Encrypt Alice Private Key (with key derivation from Alice Secret Key)
    let context = 'private key encryption';
    let subKey = sodium.crypto_kdf_derive_from_key(KEY_BYTES, 1, context, aliceSecretKey);
    let nonce = sodium.crypto_kdf_derive_from_key(NONCE_BYTES, 2, context, aliceSecretKey);
    let aliceEncryptedPrivateKey = sodium.crypto_secretbox_easy(aliceKeyPair.privateKey, nonce, subKey);
    console.log('Alice Encrypted Private Key: ' + Buffer.from(aliceEncryptedPrivateKey).toString('base64'));

    // Decrypt Alice Private Key (for testing)
    let aliceDecryptedPrivateKey = sodium.crypto_secretbox_open_easy(aliceEncryptedPrivateKey, nonce, subKey);
    console.log('Alice Decrypted Private Key: ' + Buffer.from(aliceDecryptedPrivateKey).toString('base64'));

    console.log('------------------------------------------------------------------------');

    // Generate Bob Secret Key
    let bobSecretKey = sodium.randombytes_buf(32);
    // let secretKey = base32.encode(rand).toUpperCase().replace(/=/g, '');
    console.log('Bob Secret Key: ' + Buffer.from(bobSecretKey).toString('base64'));

    // Generate Bob Key Pair
    let bobKeyPair = sodium.crypto_box_keypair();
    console.log('Bob Private Key: ' + Buffer.from(bobKeyPair.publicKey).toString('base64'));

    // Encrypt Bob Private Key (with key derivation from Bob Secret Key)
    subKey = sodium.crypto_kdf_derive_from_key(KEY_BYTES, 1, context, bobSecretKey);
    nonce = sodium.crypto_kdf_derive_from_key(NONCE_BYTES, 2, context, bobSecretKey);
    let bobEncryptedPrivateKey = sodium.crypto_secretbox_easy(bobKeyPair.privateKey, nonce, subKey);
    console.log('Bob Encrypted Private Key: ' + Buffer.from(bobEncryptedPrivateKey).toString('base64'));

    // Send the Encrypted Private Keys to the server
    // TODO

    console.log('------------------------------------------------------------------------');

    // Create a Vault
    let vaultKey = sodium.randombytes_buf(32);
    let vault = {
        'name': 'Test vault',
        'items': []
    }
    console.log('Vault Key: ' + Buffer.from(vaultKey).toString('base64'));

    // Encrypt the vault key with Alice Public Key
    let aliceEncryptedVaultKey = sodium.crypto_box_seal(vaultKey, aliceKeyPair.publicKey);
    console.log('Alice Encrypted Vault Key: ' + Buffer.from(aliceEncryptedVaultKey).toString('base64'));

    // Decrypt the Vault Key
    let aliceDecryptedVaultKey = sodium.crypto_box_seal_open(aliceEncryptedVaultKey, aliceKeyPair.publicKey, aliceKeyPair.privateKey);
    console.log('Alice Decrypted Vault key: ' + Buffer.from(aliceDecryptedVaultKey).toString('base64'));

    // Encrypt the vault key with Bob Public Key
    let bobEncryptedVaultKey = sodium.crypto_box_seal(vaultKey, bobKeyPair.publicKey);
    console.log('Bob Encrypted Vault Key: ' + Buffer.from(bobEncryptedVaultKey).toString('base64'));

    // Decrypt the Vault Key with Bob
    let bobDecryptedVaultKey = sodium.crypto_box_seal_open(bobEncryptedVaultKey, bobKeyPair.publicKey, bobKeyPair.privateKey);
    console.log('Bob Decrypted Vault key: ' + Buffer.from(bobDecryptedVaultKey).toString('base64'));

    // Send the Vault and the Alice Encrypted Vault Key to the server
    // TODO

    console.log('------------------------------------------------------------------------');

    // Create an "Item" (json)
    let item = {
        'name': 'Test item',
        'data': {
            'password': 'super-secure-password'
        }
    };
    console.log('Plain Item data: ' +  JSON.stringify(item.data));

    // Add the Item to the Vault
    vault.items.push(item);

    // Encrypt the Vault Items with Alice Vault Key
    let encryptedItem = vault.items[0];
    context = 'vault data encryption';
    subKey = sodium.crypto_kdf_derive_from_key(KEY_BYTES, 1, context, aliceDecryptedVaultKey);
    nonce = sodium.crypto_kdf_derive_from_key(NONCE_BYTES, 2, context, aliceDecryptedVaultKey);
    let encryptedItemData = sodium.crypto_secretbox_easy(JSON.stringify(encryptedItem.data), nonce, subKey);
    console.log('Alice Encrypted Item data: ' + Buffer.from(encryptedItemData).toString('base64'));

    // Send the new Vault content to the server
    // TODO

    // Decrypt the Vault Items with the Bob Vault Key
    subKey = sodium.crypto_kdf_derive_from_key(KEY_BYTES, 1, context, bobDecryptedVaultKey);
    nonce = sodium.crypto_kdf_derive_from_key(NONCE_BYTES, 2, context, bobDecryptedVaultKey);
    let decryptedItem = sodium.crypto_secretbox_open_easy(encryptedItemData, nonce, subKey);
    console.log('Bob Decrypted Item data: ' + Buffer.from(decryptedItem).toString("ascii"));

})();
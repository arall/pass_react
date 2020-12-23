## Security
All the encryption and key generation happens in the client side. The server will NOT store any vault keys, neither user secret keys.

Once a user registers, we will ask to create a master password. That password will be used for login in and authenticate with the server, as well as for decrypting local browser data (HTML5 Web Storage).

Also, a secret key will be randomly generated (on the client side) and the user will be asked to store it safely. That secret key will never be sent to the server. Using that secret key as a passphrase, a key pair (private and public key) will be generated (also on the client side), and stored in the server. The public key will be used by the server for encrypting the data, and the private key (together with the secret key) will be used by the client, to decrypt it.

The client will store the private key and the master key, encrypted by the user master password. Once the user sign in from a new session, the server will provide the private key.

When a vault is created, a vault key is randomly generated and encrypted with each users public keys that has access to the vault (again on client side). The users will receive the vault password (encrypted with their public key) on their next sync, and they will be able to decrypt and encrypt the vault content with their private key. Again, the server will never store any vault key.

When a new user is added into a vault, the vault key will be obtained from the user who provided access to that vault. Its own client will decrypt the vault key, encrypt it using the user public key, and transfer it to the server. If there is no user with access to a vault, the vault key will not be able to be recovered anymore.

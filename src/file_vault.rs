
/// A Vault for storing secret keys.
///
/// A Vault can be created from a password and a password security level, or can be decoded from an 
/// encrypted byte vector. It holds private keys and symmetric secret keys, which can be used 
/// through the Vault interface to create a [`Lockbox`] or to sign hashes.
///
/// [`Lockbox`]: ./struct.Lockbox.html
pub struct Vault {
    config: PasswordConfig,
    root_key: SecretKey,
    perm_keys: HashMap <Key, FullKey>,
    perm_streams: HashMap <StreamKey, FullStreamKey>,
    temp_keys: HashMap <Key, FullKey>,
    temp_streams: HashMap <StreamKey, FullStreamKey>,
}

impl Vault {

    /// Create a brand-new empty Vault. Can fail if the OS doesn't let us allocate enough memory 
    /// for the password hashing algorithm, or if the password is too short or too long.
    /// 
    /// Consumes the password string in the process and zeroes it out before dropping it.
    pub fn new_from_password(security: PasswordLevel, password: String) -> Result<Vault, ()> {
        let config = match security {
            PasswordLevel::Interactive => PasswordConfig::interactive(),
            PasswordLevel::Moderate => PasswordConfig::moderate(),
            PasswordLevel::Sensitive => PasswordConfig::sensitive(),
        };
        let root_key = sodium::password_to_key(password, &config)?;
        Ok(Vault {
            config,
            root_key,
            perm_keys: Default::default(),
            perm_streams: Default::default(),
            temp_keys: Default::default(),
            temp_streams: Default::default(),
        })
    }

    /// Write the entire keystore out to a file.
    pub fn write_to_file(&self, f: &mut File) -> std::io::Result<()> {
        f.write_all(&self.encode()[..])?;
        f.sync_data()?;
        Ok(())
    }

    /// Encrypt the entire keystore and pass it out as a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        // Write the PasswordConfig, then all perm_keys, then all perm_streams
        let mut data = Vec::with_capacity(
            PasswordConfig::len() +
            self.perm_keys.len() * (1+FullKey::max_len()) +
            self.perm_streams.len() * (1+FullStreamKey::max_len())
            );
        self.config.encode(&mut data);
        let nonce = Nonce::new();
        data.extend_from_slice(&nonce.0);
        let start_of_keys = data.len();
        // Data encoded here is all in plaintext. From here through the end of 
        // sodium::aead_encrypt, nothing must be allowed to fail or panic unless 
        // it zeroes out the data using sodium::memzero beforehand.
        for key in self.perm_keys.values() {
            data.push(1u8);
            key.encode(&mut data);
        }
        for key in self.perm_streams.values() {
            data.push(2u8);
            key.encode(&mut data);
        }
        let tag = {
            let (pre_data, mut key_data) = data.split_at_mut(start_of_keys);
            sodium::aead_encrypt(&mut key_data, &pre_data, &nonce, &self.root_key)
        };
        data.extend_from_slice(&tag.0);
        data
    }

    /// Read the entire keystore from a file, returning a Vault.
    /// 
    /// Consumes the password string in the process and zeroes it out before dropping it.
    pub fn read_from_file(f: &mut File, password: String) -> io::Result<Self> {
        let mut buf_reader = BufReader::new(f);
        let mut content = Vec::new();
        buf_reader.read_to_end(&mut content)?;
        Self::decode(content, password)
    }

    /// Read a keystore from a byte vector, returning a Vault. Consumes both the byte vector and 
    /// the password string. The byte vector is used for in-place decryption, then is zeroed out. 
    /// The password string is likewise zeroed out.
    pub fn decode(mut content: Vec<u8>, password: String) -> io::Result<Self> {
        if content.len() < (PasswordConfig::len() + Nonce::len() + Tag::len()) {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "Password file does not contain any encryption info"));
        }
        let (rd, key_list) = content.split_at_mut(PasswordConfig::len() + Nonce::len());
        let mut rd = &*rd;
        let rd_start = rd;
        let config = PasswordConfig::decode(&mut rd)?;
        let root_key = sodium::password_to_key(password, &config)
            .map_err(|_e| io::Error::new(ErrorKind::InvalidData, "Password hashing failed"))?;
        let mut nonce: Nonce = Default::default();
        rd.read_exact(&mut nonce.0)?;
        let mut vault = Vault {
            config,
            root_key: root_key.clone(),
            perm_keys: Default::default(),
            perm_streams: Default::default(),
            temp_keys: Default::default(),
            temp_streams: Default::default(),
        };
        let m_len = key_list.len() - Tag::len();
        let (mut key_list, tag) = key_list.split_at_mut(m_len);
        let success = sodium::aead_decrypt(
            &mut key_list,
            &rd_start,
            &tag,
            &nonce,
            &root_key
        );
        if !success {
            sodium::memzero(key_list);
            return Err(io::Error::new(ErrorKind::InvalidInput, "Bad password or corrupted file"));
        }
        let mut success = true;
        {
            let mut rd = &*key_list;
            while !rd.is_empty() && success {
                let record_type = rd.read_u8()?;
                success = match record_type {
                    1u8 => {
                        if let Ok((key, _)) = FullKey::decode(&mut rd) {
                            let key_ref = key.get_key_ref();
                            vault.perm_keys.insert(key_ref, key);
                            true
                        }
                        else {
                            false
                        }
                    },
                    2u8 => {
                        if let Ok(stream) = FullStreamKey::decode(&mut rd) {
                            let stream_ref = stream.get_stream_ref();
                            vault.perm_streams.insert(stream_ref, stream);
                            true
                        }
                        else {
                            false
                        }
                    },
                    _ => false,
                };
            }
        }
        sodium::memzero(key_list);
        if success {
            Ok(vault)
        }
        else {
            Err(io::Error::new(ErrorKind::InvalidData, "Failed to read key"))
        }
    }

    /// Create a new key and add to permanent store.
    pub fn new_key(&mut self) -> Key {
        let (k, _id) = FullKey::new_pair().unwrap();
        let key_ref = k.get_key_ref();
        self.perm_keys.insert(key_ref.clone(),k);
        key_ref
    }

    /// Create a new Stream and add to permanent store.
    pub fn new_stream(&mut self) -> StreamKey {
        let k = FullStreamKey::new();
        let k_ref = k.get_stream_ref();
        self.perm_streams.insert(k_ref.clone(), k);
        k_ref
    }

    /// Moves the given key to the permanent store. Returns true if key exists and is in the 
    /// permanent store.
    pub fn key_to_perm(&mut self, k: &Key) -> bool {
        // Move key and hold onto FullKey if needed to reconstruct identity
        match self.temp_keys.remove(&k) {
            Some(key) => {
                self.perm_keys.insert(k.clone(),key);
                true
            },
            None => self.perm_keys.contains_key(&k)
        }
    }

    /// Moves the given Stream to the permanent store. Returns true if Stream exists and is in the 
    /// permanent store.
    pub fn stream_to_perm(&mut self, stream: &StreamKey) -> bool {
        match self.temp_streams.remove(&stream) {
            Some(full_stream) => {self.perm_streams.insert(stream.clone(),full_stream); true},
            None => self.perm_streams.contains_key(&stream),
        }
    }

    /// Checks to see if we have the given Stream.
    pub fn has_stream(&self, stream: &StreamKey) -> bool {
        self.perm_streams.contains_key(stream) || self.temp_streams.contains_key(stream)
    }

    /// Checks to see if we know the Key for the given Identity.
    pub fn owns_identity(&self, id: &Identity) -> bool {
        let key = key::key_from_identity(id);
        self.perm_keys.contains_key(&key) || self.temp_keys.contains_key(&key)
    }

    /// Checks to see if we have the given Key.
    pub fn has_key(&self, key: &Key) -> bool {
        self.perm_keys.contains_key(key) || self.temp_keys.contains_key(key)
    }

    /// Drops the given key from every store.
    pub fn drop_key(&mut self, k: Key) {
        self.perm_keys.remove(&k);
        self.temp_keys.remove(&k);
    }

    /// Drops the given stream from every store.
    pub fn drop_stream(&mut self, stream: StreamKey) {
        self.perm_streams.remove(&stream);
        self.temp_streams.remove(&stream);
    }

    pub fn sign(&self, hash: &Hash, key: &Key) -> Result<Signature, CryptoError> {
        let key = self.get_key(key)?;
        Ok(key.sign(hash))
    }

    fn data_from_lockbox_content(&self, data: LockboxContent) -> Result<Vec<u8>, CryptoError> {
        let m = match data {
            LockboxContent::Key(k) => {
                let mut m = vec![LockboxType::Key.into_u8()];
                self.get_key(&k)?.encode(&mut m);
                m
            },
            LockboxContent::StreamKey(sk) => {
                let mut m = vec![LockboxType::StreamKey.into_u8()];
                self.get_stream(&sk)?.encode(&mut m);
                m
            },
            LockboxContent::Data(mut d) => {
                d.insert(0, LockboxType::Data.into_u8());
                d
            },
        };
        Ok(m)
    }

    /// Create a Lockbox using a StreamKey.
    pub fn encrypt_using_stream(&self, data: LockboxContent, stream: &StreamKey) -> Result<Lockbox, CryptoError> {
        let message = self.data_from_lockbox_content(data)?;
        let stream_key = self.get_stream(stream)?;
        lockbox::lockbox_from_stream(stream_key, message)
    }

    /// Create a Lockbox using an Identity.
    pub fn encrypt_using_identity(&self, data: LockboxContent, id: &Identity) -> Result<Lockbox, CryptoError> {
        let message = self.data_from_lockbox_content(data)?;
        let full_id = FullIdentity::from_identity(id)?;
        let (lock, _) = lockbox::lockbox_from_identity(&full_id, message)?;
        Ok(lock)
    }

    /// Create a Lockbox using an Identity and keep the StreamKey used for it.
    pub fn encrypt_using_identity_keep_key(&mut self, data: LockboxContent, id: &Identity) -> Result<(Lockbox, StreamKey), CryptoError> {
        let message = self.data_from_lockbox_content(data)?;
        let full_id = FullIdentity::from_identity(id)?;
        let (lock, stream_key) = lockbox::lockbox_from_identity(&full_id, message)?;
        let stream_key_ref = stream_key.get_stream_ref();
        self.perm_streams.insert(stream_key_ref.clone(), stream_key);
        Ok((lock, stream_key_ref))
    }

    /// Attempt to open a Lockbox and return the contents
    pub fn decrypt(&mut self, lock: Lockbox) -> Result<LockboxContent, CryptoError> {
        let mut data = if lock.uses_stream() {
            let stream = lock.get_stream().expect("Lockbox claimed to have stream, but didn't");
            let key = self.get_stream(&stream)?;
            lockbox::decrypt_lockbox(key, lock)?
        }
        else {
            let key = lockbox::get_key(&lock).expect("Lockbox claimed to have identity, but didn't");
            let key = self.get_key(&key)?;
            let key = lockbox::stream_key_from_lockbox(&key, &lock)?;
            lockbox::decrypt_lockbox(&key, lock)?
        };
        if data.len() < 2 { return Err(CryptoError::BadFormat); }
        match LockboxType::from_u8(data[0]) {
            Some(LockboxType::Key) => {
                let (full_key, _) = FullKey::decode(&mut &data[1..])?;
                let key = full_key.get_key_ref();
                self.temp_keys.insert(key.clone(), full_key);
                Ok(LockboxContent::Key(key))
            }
            Some(LockboxType::StreamKey) => {
                let full_stream = FullStreamKey::decode(&mut &data[1..])?;
                let stream = full_stream.get_stream_ref();
                self.temp_streams.insert(stream.clone(), full_stream);
                Ok(LockboxContent::StreamKey(stream))
            }
            Some(LockboxType::Data) => {
                data.remove(0);
                Ok(LockboxContent::Data(data))
            }
            None => Err(CryptoError::BadFormat)
        }
    }

    fn get_key(&self, k: &Key) -> Result<&FullKey, CryptoError> {
        self.perm_keys.get(k).or_else(|| self.temp_keys.get(k)).ok_or(CryptoError::NotInStorage)
    }

    fn get_stream(&self, s: &StreamKey) -> Result<&FullStreamKey, CryptoError> {
        self.perm_streams.get(s).or_else(|| self.temp_streams.get(s)).ok_or(CryptoError::NotInStorage)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    #[test]
    fn file_setup() {
        init().unwrap();
        let password = "mySuperGoodPassword";
        let mut vault = Vault::new_from_password(PasswordLevel::Interactive, String::from(password)).unwrap();
        let key = vault.new_key();
        let stream = vault.new_stream();
        {
            let mut f = std::fs::OpenOptions::new().write(true).read(true).create(true)
                .open("crypto_file_setup_test.pwfile").unwrap();
            vault.write_to_file(&mut f).unwrap();
            f.sync_data().unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            let vault2 = Vault::read_from_file(&mut f, String::from(password)).unwrap();
            assert!(vault2.has_stream(&stream));
            assert!(vault2.has_key(&key));
            assert!(vault2.owns_identity(&key.get_identity()));
        }
        std::fs::remove_file("crypto_file_setup_test.pwfile").unwrap();
    }

    /*
    #[test]
    fn stream_encrypt_value() {
        // Setup keys
        init().unwrap();
        let mut vault = Vault::new();
        let stream = vault.new_stream();
        // Run test on data
        let data = Value::from("test");
        let encrypted = vault.encrypt_stream(LockboxContents::Value(data.clone()), &stream).unwrap();
        let (key_option, stream_d, data_d)  = vault.decrypt(encrypted).unwrap();
        let data_d = match data_d {
            LockboxContents::Value(v) => v,
            _ => panic!("Lockbox should contain a value!"),
        };
        assert_eq!(stream, stream_d);
        assert_eq!(data, data_d);
        assert_eq!(key_option, None);
    }

    #[test]
    fn identity_encrypt_value() {
        // Setup keys
        init().unwrap();
        let mut vault = Vault::new();
        let key = vault.new_key();
        let id = key.get_identity();
        // Run test on data
        let data = Value::from("test");
        let (stream, encrypted) = vault.encrypt_for(LockboxContents::Value(data.clone()), &id).unwrap();
        let (key_option, stream_d, data_d)  = vault.decrypt(encrypted).unwrap();
        let data_d = match data_d {
            LockboxContents::Value(v) => v,
            _ => panic!("Lockbox should contain a value!"),
        };
        assert_eq!(stream, stream_d);
        assert_eq!(data, data_d);
        assert_eq!(key_option, Some(key));
    }

    #[test]
    fn stream_encrypt_key() {
        // Setup keys
        init().unwrap();
        let mut vault = Vault::new();
        let key = vault.new_key();
        let stream = vault.new_stream();
        // Run test on data
        let data = vault.new_key();
        let encrypted = vault.encrypt_stream(LockboxContents::Key(data.clone()), &stream).unwrap();
        let (key_option, stream_d, data_d)  = vault.decrypt(encrypted).unwrap();
        let data_d = match data_d {
            LockboxContents::Key(k) => k,
            _ => panic!("Lockbox should contain a value!"),
        };
        assert_eq!(stream, stream_d);
        assert_eq!(data, data_d);
        assert_eq!(key_option, None);
    }

    #[test]
    fn identity_encrypt_key() {
        // Setup keys
        init().unwrap();
        let mut vault = Vault::new();
        let key = vault.new_key();
        let id = key.get_identity();
        let data = Value::from("test");
        // Run test on data
        let data = vault.new_key();
        let (stream, encrypted) = vault.encrypt_for(LockboxContents::Key(data.clone()), &id).unwrap();
        let (key_option, stream_d, data_d)  = vault.decrypt(encrypted).unwrap();
        let data_d = match data_d {
            LockboxContents::Key(k) => k,
            _ => panic!("Lockbox should contain a value!"),
        };
        assert_eq!(stream, stream_d);
        assert_eq!(data, data_d);
        assert_eq!(key_option, Some(key));
    }

    #[test]
    fn stream_encrypt_stream() {
        // Setup keys
        init().unwrap();
        let mut vault = Vault::new();
        let stream = vault.new_stream();
        // Run test on data
        let data = vault.new_stream();
        let encrypted = vault.encrypt_stream(LockboxContents::StreamKey(data.clone()), &stream).unwrap();
        let (key_option, stream_d, data_d)  = vault.decrypt(encrypted).unwrap();
        let data_d = match data_d {
            LockboxContents::StreamKey(s) => s,
            _ => panic!("Lockbox should contain a value!"),
        };
        assert_eq!(stream, stream_d);
        assert_eq!(data, data_d);
        assert_eq!(key_option, None);
    }

    #[test]
    fn identity_encrypt() {
        // Setup keys
        init().unwrap();
        let mut vault = Vault::new();
        let key = vault.new_key();
        let id = key.get_identity();
        // Run test on data
        let data = vault.new_stream();
        let (stream, encrypted) = vault.encrypt_for(LockboxContents::StreamKey(data.clone()), &id).unwrap();
        let (key_option, stream_d, data_d)  = vault.decrypt(encrypted).unwrap();
        let data_d = match data_d {
            LockboxContents::StreamKey(s) => s,
            _ => panic!("Lockbox should contain a value!"),
        };
        assert_eq!(stream, stream_d);
        assert_eq!(data, data_d);
        assert_eq!(key_option, Some(key));
    }
    */
}

module PGP
  class Encryptor < org.sgonyea.pgp.Encryptor
    include_package "org.bouncycastle.openpgp"
    java_import "org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator"

    def initialize(key_string=nil)
      super()
      add_keys(key_string) if key_string
    end

    def add_keys(key_string)
      key_enumerator = keyring_from_string(key_string).get_key_rings
      add_keys_from_enumerator(key_enumerator)
    end

    def add_keys_from_file(filename)
      key_enumerator = keyring_from_file(filename).get_key_rings
      add_keys_from_enumerator(key_enumerator)
    end

    def encrypt(cleartext, filename=nil, mtime=nil)
      name    = filename.to_s if filename
      bytes   = cleartext.to_java_bytes
      mtime ||= PGP.time_now

      _encrypt(bytes, name, mtime)
    end

    def encrypt_file(file_path)
      name  = File.basename(file_path)
      bytes = File.read(file_path).to_java_bytes

      _encrypt(bytes, name, File.mtime(file_path))
    end

    protected
    def _encrypt(bytes, name, modification_time=nil)
      encrypted_bytes   = encrypt_bytes(bytes, name, modification_time)
      encrypted_string  = String.from_java_bytes(encrypted_bytes)
    end

    def add_keys_from_enumerator(key_enumerator)
      key_enumerator.each do |pk_ring|
        pk_enumerator = pk_ring.get_public_keys

        pk_enumerator.each do |key|
          next unless key.is_encryption_key

          add_public_key key
        end
      end
    end

    def keyring_from_file(filename)
      file = File.open(filename)
      keyring_from_stream(file.to_inputstream)
    end

    def keyring_from_string(key_string)
      keyring_from_stream PGP.string_to_bais(key_string)
    end

    def keyring_from_stream(stream)
      yafs = PGPUtil.get_decoder_stream(stream)
      PGPPublicKeyRingCollection.new(yafs, JcaKeyFingerprintCalculator.new)
    end

  end
end

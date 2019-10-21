package com.apelearn.cryto.common.crypto.asymmetric;

import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.CryptoException;
import com.apelearn.cryto.common.crypto.KeyGenerator;
import com.apelearn.cryto.common.crypto.symmetric.Base64;
import com.apelearn.cryto.common.crypto.symmetric.SymmetricAlgorithm;
import com.apelearn.cryto.common.crypto.util.CharsetUtil;
import com.apelearn.cryto.common.crypto.util.RadixUtil;
import com.apelearn.cryto.common.crypto.util.StrUtil;


import javax.crypto.Cipher;
import java.security.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 非对称加密算法<br>
 * 1、签名：使用私钥加密，公钥解密。用于让所有公钥所有者验证私钥所有者的身份并且用来防止私钥所有者发布的内容被篡改，但是不用来保证内容不被他人获得。<br>
 * 2、加密：用公钥加密，私钥解密。用于向公钥所有者发布信息,这个信息可能被他人篡改,但是无法被他人获得。
 * @author Looly
 * TODO 针对字节的加密解密处理，目前还没搞的太清楚，公私钥对的处理
 */
public class AsymmetricCrypto implements Crypto {

	/** 算法 */
	protected String algorithm;
	/** 公钥 */
	protected PublicKey publicKey;
	/** 私钥 */
	protected PrivateKey privateKey;
	/** Cipher负责完成加密或解密工作 */
	protected Cipher clipher;
	/** 签名，用于签名和验证 */
	protected Signature signature;
	
	protected Lock lock = new ReentrantLock();

	// ------------------------------------------------------------------ Constructor start
	/**
	 * 构造，创建新的私钥公钥对
	 * @param algorithm {@link com.apelearn.cryto.common.crypto.symmetric.SymmetricCrypto}
	 */
	public AsymmetricCrypto(AsymmetricAlgorithm algorithm) {
		this(algorithm, (byte[])null, (byte[])null);
	}
	
	/**
	 * 构造，创建新的私钥公钥对
	 * @param algorithm 算法
	 */
	public AsymmetricCrypto(String algorithm) {
		this(algorithm, (byte[])null, (byte[])null);
	}
	
	/**
	 * 构造
	 * 私钥和公钥同时为空时生成一对新的私钥和公钥<br>
	 * 私钥和公钥可以单独传入一个，如此则只能使用此钥匙来做加密或者解密
	 * @param algorithm {@link SymmetricAlgorithm}
	 * @param privateKeyBase64 私钥Base64
	 * @param publicKeyBase64 公钥Base64
	 */
	public AsymmetricCrypto(AsymmetricAlgorithm algorithm, String privateKeyBase64, String publicKeyBase64) {
		this(algorithm.getValue(), Base64.decode(privateKeyBase64), Base64.decode(publicKeyBase64));
	}
	
	/**
	 * 构造
	 * 私钥和公钥同时为空时生成一对新的私钥和公钥<br>
	 * 私钥和公钥可以单独传入一个，如此则只能使用此钥匙来做加密或者解密
	 * @param algorithm {@link SymmetricAlgorithm}
	 * @param privateKey 私钥
	 * @param publicKey 公钥
	 */
	public AsymmetricCrypto(AsymmetricAlgorithm algorithm, byte[] privateKey, byte[] publicKey) {
		this(algorithm.getValue(), privateKey, publicKey);
	}
	
	/**
	 * 构造
	 * 私钥和公钥同时为空时生成一对新的私钥和公钥<br>
	 * 私钥和公钥可以单独传入一个，如此则只能使用此钥匙来做加密或者解密
	 * @param algorithm {@link SymmetricAlgorithm}
	 * @param privateKey 私钥
	 * @param publicKey 公钥
	 * @since 3.1.1
	 */
	public AsymmetricCrypto(AsymmetricAlgorithm algorithm, PrivateKey privateKey, PublicKey publicKey) {
		this(algorithm.getValue(), privateKey, publicKey);
	}
	
	/**
	 * 构造
	 * 私钥和公钥同时为空时生成一对新的私钥和公钥<br>
	 * 私钥和公钥可以单独传入一个，如此则只能使用此钥匙来做加密或者解密
	 * @param algorithm 非对称加密算法
	 * @param privateKeyBase64 私钥Base64
	 * @param publicKeyBase64 公钥Base64
	 */
	public AsymmetricCrypto(String algorithm, String privateKeyBase64, String publicKeyBase64) {
		this(algorithm, Base64.decode(privateKeyBase64), Base64.decode(publicKeyBase64));
	}

	/**
	 * 构造
	 * 
	 * 私钥和公钥同时为空时生成一对新的私钥和公钥<br>
	 * 私钥和公钥可以单独传入一个，如此则只能使用此钥匙来做加密或者解密
	 * 
	 * @param algorithm 算法
	 * @param privateKey 私钥
	 * @param publicKey 公钥
	 */
	public AsymmetricCrypto(String algorithm, byte[] privateKey, byte[] publicKey) {
		init(algorithm, privateKey, publicKey);
	}
	
	/**
	 * 构造
	 * 
	 * 私钥和公钥同时为空时生成一对新的私钥和公钥<br>
	 * 私钥和公钥可以单独传入一个，如此则只能使用此钥匙来做加密或者解密
	 * 
	 * @param algorithm 算法
	 * @param privateKey 私钥
	 * @param publicKey 公钥
	 * @since 3.1.1
	 */
	public AsymmetricCrypto(String algorithm, PrivateKey privateKey, PublicKey publicKey) {
		init(algorithm, privateKey, publicKey);
	}
	// ------------------------------------------------------------------ Constructor end

	/**
	 * 初始化<br>
	 * 私钥和公钥同时为空时生成一对新的私钥和公钥<br>
	 * 私钥和公钥可以单独传入一个，如此则只能使用此钥匙来做加密或者解密<br>
	 * 签名默认使用MD5摘要算法，如果需要自定义签名算法，调用 {@link AsymmetricCrypto#setSignature(Signature)}设置签名对象
	 * 
	 * @param algorithm 算法
	 * @param privateKey 私钥
	 * @param publicKey 公钥
	 * @return {@link AsymmetricCrypto}
	 */
	public AsymmetricCrypto init(String algorithm, byte[] privateKey, byte[] publicKey) {
		final PrivateKey privateKeyObj = (null == privateKey) ? null : KeyGenerator.generatePrivateKey(algorithm, privateKey);
		final PublicKey publicKeyObj = (null == publicKey) ? null : KeyGenerator.generatePublicKey(algorithm, publicKey);
		
		return init(algorithm, privateKeyObj, publicKeyObj);
	}
	
	/**
	 * 初始化<br>
	 * 私钥和公钥同时为空时生成一对新的私钥和公钥<br>
	 * 私钥和公钥可以单独传入一个，如此则只能使用此钥匙来做加密或者解密<br>
	 * 签名默认使用MD5摘要算法，如果需要自定义签名算法，调用 {@link AsymmetricCrypto#setSignature(Signature)}设置签名对象
	 * 
	 * @param algorithm 算法
	 * @param privateKey 私钥
	 * @param publicKey 公钥
	 * @return {@link AsymmetricCrypto}
	 */
	public AsymmetricCrypto init(String algorithm, PrivateKey privateKey, PublicKey publicKey) {
		this.algorithm = algorithm;
		try {
			this.clipher = Cipher.getInstance(algorithm);
			this.signature = Signature.getInstance("MD5with" + algorithm);//默认签名算法
		} catch (Exception e) {
			throw new CryptoException(e);
		}
		
		if(null == privateKey && null == publicKey){
			initKeys();
		}else{
			if(null != privateKey){
				this.privateKey = privateKey;
			}
			if(null != publicKey){
				this.publicKey = publicKey;
			}
		}
		return this;
	}
	
	/**
	 * 生成公钥和私钥
	 * @return {@link AsymmetricCrypto}
	 */
	public AsymmetricCrypto initKeys() {
		KeyPair keyPair = KeyGenerator.generateKeyPair(this.algorithm);
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
		return this;
	}

	// --------------------------------------------------------------------------------- Sign and Verify
	/**
	 * 用私钥对信息生成数字签名
	 * 
	 * @param data 加密数据
	 * @return 签名
	 */
	public byte[] sign(byte[] data) {
		try {
			signature.initSign(this.privateKey);
			signature.update(data);
			return signature.sign();
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}
	
	/**
	 * 用公钥检验数字签名的合法性
	 * 
	 * @param data 数据
	 * @param sign 签名
	 * @return 是否验证通过
	 */
	public boolean verify(byte[] data, byte[] sign) {
		try {
			signature.initVerify(this.publicKey);
			signature.update(data);
			return signature.verify(sign);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	// --------------------------------------------------------------------------------- Encrypt
	/**
	 * 加密
	 * 
	 * @param data 被加密的bytes
	 * @param keyType 私钥或公钥 {@link KeyType}
	 * @return 加密后的bytes
	 */
	public byte[] encrypt(byte[] data, KeyType keyType) {
		lock.lock();
		try {
			clipher.init(Cipher.ENCRYPT_MODE, getKeyByType(keyType));
			return clipher.doFinal(data);
		} catch (Exception e) {
			throw new CryptoException(e);
		} finally {
			lock.unlock();
		}
	}

	/**
	 * 加密
	 * 
	 * @param data 被加密的字符串
	 * @param charset 编码
	 * @param keyType 私钥或公钥 {@link KeyType}
	 * @return 加密后的bytes
	 */
	public byte[] encrypt(String data, String charset, KeyType keyType) {
		return encrypt(StrUtil.bytes(data, charset), keyType);
	}

	/**
	 * 加密，使用UTF-8编码
	 * 
	 * @param data 被加密的字符串
	 * @param keyType 私钥或公钥 {@link KeyType}
	 * @return 加密后的bytes
	 */
	public byte[] encrypt(String data, KeyType keyType) {
		return encrypt(StrUtil.bytes(data, CharsetUtil.CHARSET_UTF_8), keyType);
	}

	@Override
	public String encrypt(String src, String charset) {
		return RadixUtil.toHex(
				encrypt(StrUtil.bytes(src, CharsetUtil.charset(charset)), KeyType.PublicKey));
	}

	/**
	 * 加密，使用UTF-8编码
	 * @param data 被加密的字符串
	 * @return 加密后的十六进制
	 */
	@Override
	public String encrypt(String data){
		return RadixUtil.toHex(
		        encrypt(StrUtil.bytes(data, CharsetUtil.CHARSET_UTF_8), KeyType.PublicKey));
	}

	// --------------------------------------------------------------------------------- Decrypt
	/**
	 * 解密
	 * @param bytes 被解密的bytes
	 * @param keyType 私钥或公钥 {@link KeyType}
	 * @return 解密后的bytes
	 */
	public byte[] decrypt(byte[] bytes, KeyType keyType) {
		lock.lock();
		try {
			clipher.init(Cipher.DECRYPT_MODE, getKeyByType(keyType));
			return clipher.doFinal(bytes);
		} catch (Exception e) {
			throw new CryptoException(e);
		} finally {
			lock.unlock();
		}
	}

    @Override
    public String decrypt(String hex){
	    return new String(
	            decrypt(RadixUtil.toBytes(hex), KeyType.PrivateKey));
    }

	@Override
	public byte[] encrypt(byte[] src) {
		return encrypt(src, KeyType.PublicKey);
	}

	@Override
	public byte[] decrypt(byte[] src) {
		return decrypt(src, KeyType.PrivateKey);
	}


	// --------------------------------------------------------------------------------- Getters and Setters
	/**
	 * 获得公钥
	 * 
	 * @return 获得公钥
	 */
	public PublicKey getPublicKey() {
		return this.publicKey;
	}
	/**
	 * 获得公钥
	 * 
	 * @return 获得公钥
	 */
	public String getPublicKeyBase64() {
		return Base64.encode(getPublicKey().getEncoded());
	}
	/**
	 * 设置公钥
	 * 
	 * @param publicKey 公钥
	 * @return 自身 {@link AsymmetricCrypto}
	 */
	public AsymmetricCrypto setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
		return this;
	}

	/**
	 * 获得私钥
	 * 
	 * @return 获得私钥
	 */
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}
	/**
	 * 获得私钥
	 * 
	 * @return 获得私钥
	 */
	public String getPrivateKeyBase64() {
		return Base64.encode(getPrivateKey().getEncoded());
	}
	/**
	 * 设置私钥
	 * 
	 * @param privateKey 私钥
	 * @return 自身 {@link AsymmetricCrypto}
	 */
	public AsymmetricCrypto setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
		return this;
	}
	
	/**
	 * 获得签名对象
	 * @return {@link Signature}
	 */
	public Signature getSignature() {
		return signature;
	}

	/**
	 * 设置签名
	 * @param signature 签名对象 {@link Signature}
	 * @return 自身 {@link AsymmetricCrypto}
	 */
	public AsymmetricCrypto setSignature(Signature signature) {
		this.signature = signature;
		return this;
	}

	/**
	 * 获得加密或解密器
	 * 
	 * @return 加密或解密
	 */
	public Cipher getClipher() {
		return clipher;
	}
	
	/**
	 * 根据密钥类型获得相应密钥
	 * @param type 类型 {@link KeyType}
	 * @return {@link Key}
	 */
	protected Key getKeyByType(KeyType type){
		switch (type) {
			case PrivateKey:
				if(null == this.privateKey){
					throw new NullPointerException("Private key must not null when use it !");
				}
				return this.privateKey;
			case PublicKey:
				if(null == this.publicKey){
					throw new NullPointerException("Public key must not null when use it !");
				}
				return this.publicKey;

            default:throw new CryptoException("Uknown key type: " + type);
		}

	}
}

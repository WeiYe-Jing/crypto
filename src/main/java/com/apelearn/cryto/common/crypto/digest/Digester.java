package com.apelearn.cryto.common.crypto.digest;


import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.CryptoException;
import com.apelearn.cryto.common.crypto.util.CharsetUtil;
import com.apelearn.cryto.common.crypto.util.IoUtil;
import com.apelearn.cryto.common.crypto.util.RadixUtil;
import com.apelearn.cryto.common.crypto.util.StrUtil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 摘要算法<br>
 * 注意：此对象实例化后为非线程安全！
 * @author Looly
 *
 */
public class Digester extends AbstractDigestCrypto implements Crypto {
	/** 默认缓存大小 */
	public static final int DEFAULT_BUFFER_SIZE = 1024;
	private MessageDigest digest;
	
	public Digester(DigestAlgorithm algorithm) {
		init(algorithm.getValue());
	}
	
	/**
	 * 初始化
	 * @param algorithm 算法
	 * @return {@link Digester}
	 * @throws CryptoException Cause by IOException
	 */
	public Digester init(String algorithm){
		try {
			digest = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}
		return this;
	}
	
	// ------------------------------------------------------------------------------------------- Digest
	/**
	 * 生成文件摘要
	 * 
	 * @param data 被摘要数据
	 * @param charset 编码
	 * @return 摘要
	 */
	public byte[] digest(String data, String charset) {
		return digest(StrUtil.bytes(data, charset));
	}
	
	/**
	 * 生成文件摘要
	 * 
	 * @param data 被摘要数据
	 * @return 摘要
	 */
	public byte[] digest(String data) {
		return digest(data, CharsetUtil.UTF_8);
	}
	
	/**
	 * 生成文件摘要，并转为16进制字符串
	 * 
	 * @param data 被摘要数据
	 * @param charset 编码
	 * @return 摘要
	 */
	public String digestHex(String data, String charset) {
		return RadixUtil.toHex(digest(data, charset));
	}

	@Override
	public String encrypt(String src, String charset) {
		return digestHex(src, charset);
	}

	/**
	 * 生成文件摘要
	 * @param data 被摘要数据
	 * @return 摘要
	 */
	@Override
	public String encrypt(String data) {
		return digestHex(data, CharsetUtil.UTF_8);
	}
	
	/**
	 * 生成文件摘要<br>
	 * 使用默认缓存大小
	 * 
	 * @param file 被摘要文件
	 * @return 摘要bytes
	 * @throws CryptoException Cause by IOException
	 */
	public byte[] digest(File file) throws CryptoException {
		InputStream in = IoUtil.getFileInputStream(file.getAbsolutePath());
		byte[] d = digest(in);
		IoUtil.close(in);
		return d;
	}
	
	/**
	 * 生成文件摘要，并转为16进制字符串<br>
	 * 使用默认缓存大小
	 * 
	 * @param file 被摘要文件
	 * @return 摘要
	 */
	public String digestHex(File file) {
		return RadixUtil.toHex(digest(file));
	}
	
	/**
	 * 生成摘要
	 * 
	 * @param data 数据bytes
	 * @return 摘要bytes
	 */
	public byte[] digest(byte[] data) {
		byte[] result;
		try {
			result = digest.digest(data);
		} finally {
			digest.reset();
		}
		return result;
	}
    @Override
    public byte[] encrypt(byte[] data) {
        return digest(data);
    }
	/**
	 * 生成摘要，并转为16进制字符串<br>
	 * 
	 * @param data 被摘要数据
	 * @return 摘要
	 */
	public String digestHex(byte[] data) {
		return RadixUtil.toHex(digest(data));
	}
	
	/**
	 * 生成摘要，使用默认缓存大小
	 * 
	 * @param data {@link InputStream} 数据流
	 * @return 摘要bytes
	 */
	public byte[] digest(InputStream data) {
		return digest(data, DEFAULT_BUFFER_SIZE);
	}
	
	/**
	 * 生成摘要，并转为16进制字符串<br>
	 * 使用默认缓存大小
	 * 
	 * @param data 被摘要数据
	 * @return 摘要
	 */
	public String digestHex(InputStream data) {
		return RadixUtil.toHex(digest(data));
	}

	/**
	 * 生成摘要
	 * 
	 * @param data {@link InputStream} 数据流
	 * @param bufferLength 缓存长度，不足1使用默认值
	 * @return 摘要bytes
	 * @throws CryptoException IO异常
	 */
	public byte[] digest(InputStream data, int bufferLength) throws CryptoException {
		if (bufferLength < 1) {
			bufferLength = DEFAULT_BUFFER_SIZE;
		}
		byte[] buffer = new byte[bufferLength];
		
		byte[] result = null;
		try {
			int read = data.read(buffer, 0, bufferLength);
			
			while (read > -1) {
				digest.update(buffer, 0, read);
				read = data.read(buffer, 0, bufferLength);
			}
			result = digest.digest();
		} catch (IOException e) {
			throw new CryptoException(e);
		}finally{
			digest.reset();
		}
		return result;
	}
	
	/**
	 * 生成摘要，并转为16进制字符串<br>
	 * 使用默认缓存大小
	 * 
	 * @param data 被摘要数据
	 * @param bufferLength 缓存长度，不足1使用默认值
	 * @return 摘要
	 */
	public String digestHex(InputStream data, int bufferLength) {
		return RadixUtil.toHex(digest(data, bufferLength));
	}
	
	/**
	 * 获得 {@link MessageDigest}
	 * @return {@link MessageDigest}
	 */
	public MessageDigest getDigest() {
		return digest;
	}
}

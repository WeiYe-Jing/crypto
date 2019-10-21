package com.apelearn.cryto.common.crypto.util;

/**
 * Stream进度条
 * @author Looly
 * @author 熊诗言
 */
public interface ProgressNotifier {
	
	/**
	 * 开始
	 */
	void start();
	
	/**
	 * 进行中
	 * @param progressedSize 当前处理的大小
	 */
	void progressed(long progressedSize);
	
	/**
	 * 结束
     * @param totalSize 处理的总大小
	 */
	void finish(long totalSize);

	/**
	 * 发生了异常
     * @param t 异常
	 */
	void error(Exception t);
}

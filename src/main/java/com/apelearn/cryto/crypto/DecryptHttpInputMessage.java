package com.apelearn.cryto.crypto;

import com.apelearn.cryto.common.crypto.Crypto;
import com.apelearn.cryto.common.crypto.util.IoUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 *
 * @author xiongshiyan
 */
public class DecryptHttpInputMessage implements HttpInputMessage {
    private HttpInputMessage inputMessage;
    private String charset;
    private Crypto crypto;

    public DecryptHttpInputMessage(HttpInputMessage inputMessage, String charset , Crypto crypto) {
        this.inputMessage = inputMessage;
        this.charset = charset;
        this.crypto = crypto;
    }

    @Override
    public InputStream getBody() throws IOException {
        String content = IoUtil.read(inputMessage.getBody() , charset);

        String decryptBody = crypto.decrypt(content, charset);

        return new ByteArrayInputStream(decryptBody.getBytes(charset));
    }

    @Override
    public HttpHeaders getHeaders() {
        return inputMessage.getHeaders();
    }
}
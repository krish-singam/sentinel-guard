package com.krish.sentinel_guard.waf.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.util.StreamUtils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Reusable HTTP Request Wrapper that caches the request body in memory
 * so that the WAF inspection engine can perform deep payload inspection
 * without exhausting the input stream for downstream controllers or proxies.
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] cachedBody;
    private final Charset characterEncoding;

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);

        String encodingName = request.getCharacterEncoding();
        this.characterEncoding = encodingName != null ? Charset.forName(encodingName) : StandardCharsets.UTF_8;

        // Cache the incoming input stream into a byte array
        if (request.getInputStream() != null) {
            this.cachedBody = StreamUtils.copyToByteArray(request.getInputStream());
        } else {
            this.cachedBody = new byte[0];
        }
    }

    @Override
    public ServletInputStream getInputStream() {
        return new CachedServletInputStream(this.cachedBody);
    }

    @Override
    public BufferedReader getReader() {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.cachedBody);
        return new BufferedReader(new InputStreamReader(byteArrayInputStream, this.characterEncoding));
    }

    /**
     * Retrieve the cached request payload as a string for WAF deep packet inspection.
     */
    public String getBodyAsString() {
        if (this.cachedBody.length == 0) {
            return "";
        }
        return new String(this.cachedBody, this.characterEncoding);
    }

    public int getBodyLength() {
        return this.cachedBody.length;
    }

    public byte[] getCachedBody() {
        return this.cachedBody;
    }

    public Charset getCachedCharacterEncoding() {
        return this.characterEncoding;
    }

    private static class CachedServletInputStream extends ServletInputStream {

        private final ByteArrayInputStream buffer;

        public CachedServletInputStream(byte[] contents) {
            this.buffer = new ByteArrayInputStream(contents);
        }

        @Override
        public int read() {
            return buffer.read();
        }

        @Override
        public boolean isFinished() {
            return buffer.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            // Synchronous reading
        }
    }
}

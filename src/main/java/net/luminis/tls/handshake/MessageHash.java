package net.luminis.tls.handshake;

import net.luminis.tls.TlsConstants;

import java.nio.ByteBuffer;

public class MessageHash extends HandshakeMessage{

    private byte[] raw;

    public MessageHash(byte[] hash) {
        raw = new byte[1 + 3 + hash.length];
        ByteBuffer buffer = ByteBuffer.wrap(raw);

        buffer.putInt(hash.length | 0xFE000000);
        buffer.put(hash);
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.message_hash;
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }
}

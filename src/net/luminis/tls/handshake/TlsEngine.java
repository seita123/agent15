/*
 * Copyright © 2020, 2021 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package net.luminis.tls.handshake;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsState;
import net.luminis.tls.TrafficSecrets;
import net.luminis.tls.alert.HandshakeFailureAlert;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PSSParameterSpec;

import static net.luminis.tls.TlsConstants.NamedGroup.*;
import static net.luminis.tls.TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256;
import static net.luminis.tls.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;

public abstract class TlsEngine implements MessageProcessor, TrafficSecrets {

    protected PublicKey publicKey;
    protected PrivateKey privateKey;
    protected TlsState state;

    public abstract TlsConstants.CipherSuite getSelectedCipher();


    protected void generateKeys(TlsConstants.NamedGroup namedGroup) {
        try {
            KeyPairGenerator keyPairGenerator;
            if (namedGroup == secp256r1 || namedGroup == secp384r1 || namedGroup == secp521r1) {
                keyPairGenerator = KeyPairGenerator.getInstance("EC");
                keyPairGenerator.initialize(new ECGenParameterSpec(namedGroup.toString()));
            }
            else if (namedGroup == x25519 || namedGroup == x448) {
                keyPairGenerator = KeyPairGenerator.getInstance("XDH");
                NamedParameterSpec paramSpec = new NamedParameterSpec(namedGroup.toString().toUpperCase());  // x25519 => X25519
                keyPairGenerator.initialize(paramSpec);
            }
            else {
                throw new RuntimeException("unsupported group " + namedGroup);
            }

            KeyPair keyPair = keyPairGenerator.genKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            // Invalid runtime
            throw new RuntimeException("missing key pair generator algorithm EC");
        } catch (InvalidAlgorithmParameterException e) {
            // Impossible, would be programming error
            throw new RuntimeException();
        }
    }

    /**
     * Compute the signature used in certificate verify message to proof possession of private key.
     * @param content  the content to be signed (transcript hash)
     * @param certificatePrivateKey  the private key associated with the certificate
     * @param client  whether the signature must be computed
     * @return
     */
    protected byte[] computeSignature(byte[] content, PrivateKey certificatePrivateKey, boolean client) {
        // https://tools.ietf.org/html/rfc8446#section-4.4.3

        //   The digital signature is then computed over the concatenation of:
        //   -  A string that consists of octet 32 (0x20) repeated 64 times
        //   -  The context string
        //   -  A single 0 byte which serves as the separator
        //   -  The content to be signed"
        ByteArrayOutputStream signatureInput = new ByteArrayOutputStream();
        try {
            signatureInput.write(new String(new byte[] { 0x20 }).repeat(64).getBytes(StandardCharsets.US_ASCII));
            String contextString = "TLS 1.3, " + (client? "client": "server") + " CertificateVerify";
            signatureInput.write(contextString.getBytes(StandardCharsets.US_ASCII));
            signatureInput.write(0x00);
            signatureInput.write(content);
        } catch (IOException e) {
            // Impossible
            throw new RuntimeException();
        }

        try {
            Signature signatureAlgorithm = Signature.getInstance("RSASSA-PSS");
            signatureAlgorithm.setParameter(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
            signatureAlgorithm.initSign(certificatePrivateKey);
            signatureAlgorithm.update(signatureInput.toByteArray());
            byte[] digitalSignature = signatureAlgorithm.sign();
            return digitalSignature;
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + "RSASSA-PSS" + " support");
        }
        catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            // Impossible
            throw new RuntimeException();
        } catch (SignatureException e) {
            throw new RuntimeException();
        }
    }

    // https://tools.ietf.org/html/rfc8446#section-4.4.4
    protected byte[] computeFinishedVerifyData(byte[] transcriptHash, byte[] baseKey) {
        short hashLength = state.getHashLength();
        byte[] finishedKey = state.hkdfExpandLabel(baseKey, "finished", "", hashLength);
        String macAlgorithmName = "HmacSHA" + (hashLength * 8);
        SecretKeySpec hmacKey = new SecretKeySpec(finishedKey, macAlgorithmName);

        try {
            Mac hmacAlgorithm = Mac.getInstance(macAlgorithmName);
            hmacAlgorithm.init(hmacKey);
            hmacAlgorithm.update(transcriptHash);
            byte[] hmac = hmacAlgorithm.doFinal();
            return hmac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + macAlgorithmName + " support");
        } catch (InvalidKeyException e) {
            throw new RuntimeException();
        }
    }

    protected Signature getSignatureAlgorithm(TlsConstants.SignatureScheme signatureScheme) throws HandshakeFailureAlert {
        Signature signatureAlgorithm = null;
        // https://tools.ietf.org/html/rfc8446#section-9.1
        // "A TLS-compliant application MUST support digital signatures with rsa_pkcs1_sha256 (for certificates),
        // rsa_pss_rsae_sha256 (for CertificateVerify and certificates), and ecdsa_secp256r1_sha256."
        if (signatureScheme.equals(rsa_pss_rsae_sha256)) {
            try {
                signatureAlgorithm = Signature.getInstance("RSASSA-PSS");
                signatureAlgorithm.setParameter(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Missing RSASSA-PSS support");
            } catch (InvalidAlgorithmParameterException e) {
                // Fairly impossible (because the parameters is hard coded)
                throw new RuntimeException(e);
            }
        }
        else if (signatureScheme.equals(ecdsa_secp256r1_sha256)) {
            try {
                signatureAlgorithm = Signature.getInstance("SHA256withECDSA");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Missing SHA256withECDSA support");
            }
        }
        else {
            // Bad lock, not yet supported.
            throw new HandshakeFailureAlert("Signature algorithm (verification) not supported " + signatureScheme);
        }
        return signatureAlgorithm;
    }

    @Override
    public byte[] getClientEarlyTrafficSecret() {
        if (state != null) {
            return state.getClientEarlyTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getClientHandshakeTrafficSecret() {
        if (state != null) {
            return state.getClientHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getServerHandshakeTrafficSecret() {
        if (state != null) {
            return state.getServerHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getClientApplicationTrafficSecret() {
        if (state != null) {
            return state.getClientApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getServerApplicationTrafficSecret() {
        if (state != null) {
            return state.getServerApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

}


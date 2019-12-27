/*
 * Copyright (c) 2010, 2016, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package xxx.sun.security.ssl;

import sun.security.util.KeyUtil;

import java.security.AlgorithmConstraints;
import java.security.CryptoPrimitive;
import java.security.PrivateKey;
import java.security.Security;
import java.util.*;

/**
 * Signature and hash algorithm.
 *
 * [RFC5246] The client uses the "signature_algorithms" extension to
 * indicate to the server which signature/hash algorithm pairs may be
 * used in digital signatures.  The "extension_data" field of this
 * extension contains a "supported_signature_algorithms" value.
 *
 *     enum {
 *         none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
 *         sha512(6), (255)
 *     } HashAlgorithm;
 *
 *     enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
 *       SignatureAlgorithm;
 *
 *     struct {
 *           HashAlgorithm hash;
 *           SignatureAlgorithm signature;
 *     } SignatureAndHashAlgorithm;
 */
final class SignatureAndHashAlgorithm {

    // minimum priority for default enabled algorithms
    final static int SUPPORTED_ALG_PRIORITY_MAX_NUM = 0x00F0;

    // performance optimization
    private final static Set<CryptoPrimitive> SIGNATURE_PRIMITIVE_SET =
        Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.SIGNATURE));

    // supported pairs of signature and hash algorithm
    private final static Map<Integer, xxx.sun.security.ssl.SignatureAndHashAlgorithm> supportedMap;
    private final static Map<Integer, xxx.sun.security.ssl.SignatureAndHashAlgorithm> priorityMap;

    // the hash algorithm
    private HashAlgorithm hash;

    // id in 16 bit MSB format, i.e. 0x0603 for SHA512withECDSA
    private int id;

    // the standard algorithm name, for example "SHA512withECDSA"
    private String algorithm;

    // Priority for the preference order. The lower the better.
    //
    // If the algorithm is unsupported, its priority should be bigger
    // than SUPPORTED_ALG_PRIORITY_MAX_NUM.
    private int priority;

    // constructor for supported algorithm
    private SignatureAndHashAlgorithm(HashAlgorithm hash,
            SignatureAlgorithm signature, String algorithm, int priority) {
        this.hash = hash;
        this.algorithm = algorithm;
        this.id = ((hash.value & 0xFF) << 8) | (signature.value & 0xFF);
        this.priority = priority;
    }

    // constructor for unsupported algorithm
    private SignatureAndHashAlgorithm(String algorithm, int id, int sequence) {
        this.hash = HashAlgorithm.valueOf((id >> 8) & 0xFF);
        this.algorithm = algorithm;
        this.id = id;

        // add one more to the sequence number, in case that the number is zero
        this.priority = SUPPORTED_ALG_PRIORITY_MAX_NUM + sequence + 1;
    }

    // Note that we do not use the sequence argument for supported algorithms,
    // so please don't sort by comparing the objects read from handshake
    // messages.
    static xxx.sun.security.ssl.SignatureAndHashAlgorithm valueOf(int hash,
                                                              int signature, int sequence) {
        hash &= 0xFF;
        signature &= 0xFF;

        int id = (hash << 8) | signature;
        xxx.sun.security.ssl.SignatureAndHashAlgorithm signAlg = supportedMap.get(id);
        if (signAlg == null) {
            // unsupported algorithm
            signAlg = new xxx.sun.security.ssl.SignatureAndHashAlgorithm(
                "Unknown (hash:0x" + Integer.toString(hash, 16) +
                ", signature:0x" + Integer.toString(signature, 16) + ")",
                id, sequence);
        }

        return signAlg;
    }

    int getHashValue() {
        return (id >> 8) & 0xFF;
    }

    int getSignatureValue() {
        return id & 0xFF;
    }

    String getAlgorithmName() {
        return algorithm;
    }

    // return the size of a SignatureAndHashAlgorithm structure in TLS record
    static int sizeInRecord() {
        return 2;
    }

    // Get local supported algorithm collection complying to
    // algorithm constraints
    static Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm>
            getSupportedAlgorithms(AlgorithmConstraints constraints) {

        Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm> supported = new ArrayList<>();
        for (xxx.sun.security.ssl.SignatureAndHashAlgorithm sigAlg : priorityMap.values()) {
            if (sigAlg.priority <= SUPPORTED_ALG_PRIORITY_MAX_NUM &&
                    constraints.permits(SIGNATURE_PRIMITIVE_SET,
                            sigAlg.algorithm, null)) {
                supported.add(sigAlg);
            }
        }

        return supported;
    }

    // Get supported algorithm collection from an untrusted collection
    static Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm> getSupportedAlgorithms(
            AlgorithmConstraints constraints,
            Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm> algorithms ) {
        Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm> supported = new ArrayList<>();
        for (xxx.sun.security.ssl.SignatureAndHashAlgorithm sigAlg : algorithms) {
            if (sigAlg.priority <= SUPPORTED_ALG_PRIORITY_MAX_NUM &&
                    constraints.permits(SIGNATURE_PRIMITIVE_SET,
                                sigAlg.algorithm, null)) {
                supported.add(sigAlg);
            }
        }

        return supported;
    }

    static String[] getAlgorithmNames(
            Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm> algorithms) {
        ArrayList<String> algorithmNames = new ArrayList<>();
        if (algorithms != null) {
            for (xxx.sun.security.ssl.SignatureAndHashAlgorithm sigAlg : algorithms) {
                algorithmNames.add(sigAlg.algorithm);
            }
        }

        String[] array = new String[algorithmNames.size()];
        return algorithmNames.toArray(array);
    }

    static Set<String> getHashAlgorithmNames(
            Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm> algorithms) {
        Set<String> algorithmNames = new HashSet<>();
        if (algorithms != null) {
            for (xxx.sun.security.ssl.SignatureAndHashAlgorithm sigAlg : algorithms) {
                if (sigAlg.hash.value > 0) {
                    algorithmNames.add(sigAlg.hash.standardName);
                }
            }
        }

        return algorithmNames;
    }

    static String getHashAlgorithmName(xxx.sun.security.ssl.SignatureAndHashAlgorithm algorithm) {
        return algorithm.hash.standardName;
    }

    private static void supports(HashAlgorithm hash,
            SignatureAlgorithm signature, String algorithm, int priority) {

        xxx.sun.security.ssl.SignatureAndHashAlgorithm pair =
            new xxx.sun.security.ssl.SignatureAndHashAlgorithm(hash, signature, algorithm, priority);
        if (supportedMap.put(pair.id, pair) != null) {
            throw new RuntimeException(
                "Duplicate SignatureAndHashAlgorithm definition, id: " +
                pair.id);
        }
        if (priorityMap.put(pair.priority, pair) != null) {
            throw new RuntimeException(
                "Duplicate SignatureAndHashAlgorithm definition, priority: " +
                pair.priority);
        }
    }

    static xxx.sun.security.ssl.SignatureAndHashAlgorithm getPreferableAlgorithm(
            Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm> algorithms, String expected) {

        return xxx.sun.security.ssl.SignatureAndHashAlgorithm.getPreferableAlgorithm(
                algorithms, expected, null);
    }

    static xxx.sun.security.ssl.SignatureAndHashAlgorithm getPreferableAlgorithm(
            Collection<xxx.sun.security.ssl.SignatureAndHashAlgorithm> algorithms,
            String expected, PrivateKey signingKey) {

        int maxDigestLength = getMaxDigestLength(signingKey);
        for (xxx.sun.security.ssl.SignatureAndHashAlgorithm algorithm : algorithms) {
            int signValue = algorithm.id & 0xFF;
            if ((expected == null) ||
                    (expected.equalsIgnoreCase("rsa") &&
                            signValue == SignatureAlgorithm.RSA.value) ||
                    (expected.equalsIgnoreCase("dsa") &&
                            signValue == SignatureAlgorithm.DSA.value) ||
                    (expected.equalsIgnoreCase("ecdsa") &&
                            signValue == SignatureAlgorithm.ECDSA.value) ||
                    (expected.equalsIgnoreCase("ec") &&
                            signValue == SignatureAlgorithm.ECDSA.value)) {

                if (algorithm.priority <= SUPPORTED_ALG_PRIORITY_MAX_NUM &&
                        algorithm.hash.length <= maxDigestLength) {

                    return algorithm;
                }
            }
        }

        return null;
    }

    /*
     * Need to check key length to match the length of hash value
     */
    private static int getMaxDigestLength(PrivateKey signingKey) {
        int maxDigestLength = Integer.MAX_VALUE;

        // only need to check RSA algorithm at present.
        if (signingKey != null &&
                "rsa".equalsIgnoreCase(signingKey.getAlgorithm())) {
            /*
             * RSA keys of 512 bits have been shown to be practically
             * breakable, it does not make much sense to use the strong
             * hash algorithm for keys whose key size less than 512 bits.
             * So it is not necessary to caculate the required max digest
             * length exactly.
             *
             * If key size is greater than or equals to 768, there is no max
             * digest length limitation in currect implementation.
             *
             * If key size is greater than or equals to 512, but less than
             * 768, the digest length should be less than or equal to 32 bytes.
             *
             * If key size is less than 512, the  digest length should be
             * less than or equal to 20 bytes.
             */
            int keySize = KeyUtil.getKeySize(signingKey);
            if (keySize >= 768) {
                maxDigestLength = HashAlgorithm.SHA512.length;
            } else if ((keySize >= 512) && (keySize < 768)) {
                maxDigestLength = HashAlgorithm.SHA256.length;
            } else if ((keySize > 0) && (keySize < 512)) {
                maxDigestLength = HashAlgorithm.SHA1.length;
            }   // Otherwise, cannot determine the key size, prefer the most
                // preferable hash algorithm.
        }

        return maxDigestLength;
    }

    static enum HashAlgorithm {
        UNDEFINED("undefined",        "", -1, -1),
        NONE(          "none",    "NONE",  0, -1),
        MD5(            "md5",     "MD5",  1, 16),
        SHA1(          "sha1",   "SHA-1",  2, 20),
        SHA224(      "sha224", "SHA-224",  3, 28),
        SHA256(      "sha256", "SHA-256",  4, 32),
        SHA384(      "sha384", "SHA-384",  5, 48),
        SHA512(      "sha512", "SHA-512",  6, 64);

        final String name;  // not the standard signature algorithm name
                            // except the UNDEFINED, other names are defined
                            // by TLS 1.2 protocol
        final String standardName; // the standard MessageDigest algorithm name
        final int value;
        final int length;   // digest length in bytes, -1 means not applicable

        private HashAlgorithm(String name, String standardName,
                int value, int length) {
            this.name = name;
            this.standardName = standardName;
            this.value = value;
            this.length = length;
        }

        static HashAlgorithm valueOf(int value) {
            HashAlgorithm algorithm = UNDEFINED;
            switch (value) {
                case 0:
                    algorithm = NONE;
                    break;
                case 1:
                    algorithm = MD5;
                    break;
                case 2:
                    algorithm = SHA1;
                    break;
                case 3:
                    algorithm = SHA224;
                    break;
                case 4:
                    algorithm = SHA256;
                    break;
                case 5:
                    algorithm = SHA384;
                    break;
                case 6:
                    algorithm = SHA512;
                    break;
            }

            return algorithm;
        }
    }

    static enum SignatureAlgorithm {
        UNDEFINED("undefined", -1),
        ANONYMOUS("anonymous",  0),
        RSA(            "rsa",  1),
        DSA(            "dsa",  2),
        ECDSA(        "ecdsa",  3);

        final String name;  // not the standard signature algorithm name
                            // except the UNDEFINED, other names are defined
                            // by TLS 1.2 protocol
        final int value;

        private SignatureAlgorithm(String name, int value) {
            this.name = name;
            this.value = value;
        }

        static SignatureAlgorithm valueOf(int value) {
            SignatureAlgorithm algorithm = UNDEFINED;
            switch (value) {
                case 0:
                    algorithm = ANONYMOUS;
                    break;
                case 1:
                    algorithm = RSA;
                    break;
                case 2:
                    algorithm = DSA;
                    break;
                case 3:
                    algorithm = ECDSA;
                    break;
            }

            return algorithm;
        }
    }

    static {
        supportedMap = Collections.synchronizedSortedMap(
            new TreeMap<Integer, xxx.sun.security.ssl.SignatureAndHashAlgorithm>());
        priorityMap = Collections.synchronizedSortedMap(
            new TreeMap<Integer, xxx.sun.security.ssl.SignatureAndHashAlgorithm>());

        synchronized (supportedMap) {
            int p = SUPPORTED_ALG_PRIORITY_MAX_NUM;
            supports(HashAlgorithm.MD5,         SignatureAlgorithm.RSA,
                    "MD5withRSA",           --p);
            supports(HashAlgorithm.SHA1,        SignatureAlgorithm.DSA,
                    "SHA1withDSA",          --p);
            supports(HashAlgorithm.SHA1,        SignatureAlgorithm.RSA,
                    "SHA1withRSA",          --p);
            supports(HashAlgorithm.SHA1,        SignatureAlgorithm.ECDSA,
                    "SHA1withECDSA",        --p);

            if (Security.getProvider("SunMSCAPI") == null) {
                supports(HashAlgorithm.SHA224,      SignatureAlgorithm.DSA,
                        "SHA224withDSA",        --p);
                supports(HashAlgorithm.SHA224,      SignatureAlgorithm.RSA,
                        "SHA224withRSA",        --p);
                supports(HashAlgorithm.SHA224,      SignatureAlgorithm.ECDSA,
                        "SHA224withECDSA",      --p);
            }

            supports(HashAlgorithm.SHA256,      SignatureAlgorithm.DSA,
                    "SHA256withDSA",        --p);
            supports(HashAlgorithm.SHA256,      SignatureAlgorithm.RSA,
                    "SHA256withRSA",        --p);
            supports(HashAlgorithm.SHA256,      SignatureAlgorithm.ECDSA,
                    "SHA256withECDSA",      --p);
            supports(HashAlgorithm.SHA384,      SignatureAlgorithm.RSA,
                    "SHA384withRSA",        --p);
            supports(HashAlgorithm.SHA384,      SignatureAlgorithm.ECDSA,
                    "SHA384withECDSA",      --p);
            supports(HashAlgorithm.SHA512,      SignatureAlgorithm.RSA,
                    "SHA512withRSA",        --p);
            supports(HashAlgorithm.SHA512,      SignatureAlgorithm.ECDSA,
                    "SHA512withECDSA",      --p);
        }
    }
}


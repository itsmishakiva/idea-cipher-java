package idea_cipher;

public class IdeaCipher {

    private final short[] key;
    final private boolean enabledCFB;

    public IdeaCipher(byte[] key, boolean enabledCFB) throws IdeaCipherException {
        if (key.length != 16) throw new IdeaCipherException("Wrong key");
        this.key = new short[8];
        for (int i = 0; i < 16; i += 2) {
            this.key[i / 2] = (short) (((key[i] << 8) & 0xFF00) | (key[i + 1] & 0xFF));
        }
        this.enabledCFB = enabledCFB;
    }

    private long generateInitializeVector(short seed) {
        return seed ^ (long) 0x78F7F8F7;
    }

    public byte[] encode(byte[] input) {
        short[] keys = generateKeys(key);
        int remainder = input.length % 8;
        short[] inputTwoBytes = new short[((input.length / 8) * 8 + 16 + (enabledCFB ? 16 : 0)) / 2];
        for (int i = 0; i < input.length; i += 2) {
            if (i == input.length - 1) inputTwoBytes[i / 2] = (short) (((input[i]) << 8) & 0xFF00);
            else inputTwoBytes[i / 2] = (short) (((input[i] << 8) & 0xFF00) | (input[i + 1] & 0xFF));
        }
        byte needsToBeRemoved = (byte) (16 - remainder + (enabledCFB ? 16 : 0));
        long vector = 0;
        if (enabledCFB) {
            vector = generateInitializeVector(inputTwoBytes[0]);
            inputTwoBytes[inputTwoBytes.length - 1] = (short) (vector & 0xFFFF);
            inputTwoBytes[inputTwoBytes.length - 2] = (short) ((vector >> 16) & 0xFFFF);
            inputTwoBytes[inputTwoBytes.length - 3] = (short) ((vector >> 32) & 0xFFFF);
            inputTwoBytes[inputTwoBytes.length - 4] = (short) ((vector >> 48) & 0xFFFF);
        }
        inputTwoBytes[inputTwoBytes.length - 1 - (enabledCFB ? 8 : 0)] = needsToBeRemoved;
        inputTwoBytes = algorithm(keys, inputTwoBytes, true, vector);
        byte[] output = new byte[inputTwoBytes.length * 2];
        for (int i = 0; i < inputTwoBytes.length; i++) {
            output[i * 2] = (byte) ((inputTwoBytes[i] >> 8) & 0xFF);
            output[i * 2 + 1] = (byte) (inputTwoBytes[i] & 0xFF);
        }
        return output;
    }

    public byte[] decode(byte[] input) {
        short[] keys = generateReversedKeys(key);
        short[] inputTwoBytes = new short[((input.length / 8) * 8) / 2];
        for (int i = 0; i < input.length - 1; i += 2) {
            inputTwoBytes[i / 2] = (short) (((input[i] << 8) & 0xFF00) | (input[i + 1] & 0xFF));
        }
        inputTwoBytes = algorithm(keys, inputTwoBytes, false, (short) 0);
        byte toRemove = (byte)(inputTwoBytes[inputTwoBytes.length - 1 - (enabledCFB ? 8 : 0)] & 0xFF);
        int newSize = inputTwoBytes.length * 2 - toRemove;
        byte[] output = new byte[newSize];
        for (int i = 0; i < newSize/2; i++) {
            output[i * 2] = (byte) ((inputTwoBytes[i] >> 8) & 0xFF);
            output[i * 2 + 1] = (byte) (inputTwoBytes[i] & 0xFF);
        }
        if (newSize % 2 == 1) {
            output[newSize - 1] = (byte) ((inputTwoBytes[(newSize - 1) / 2] >> 8) & 0xFF);
        }
        return output;
    }

    private short multiplyMod65537(long a, long b) {
        a &= 0xFFFF;
        b &= 0xFFFF;
        if (a == 0) a = 0x10000;
        if (b == 0) b = 0x10000;
        long c = a * b;
        while (c >= 65537) {
            c -= 65537;
        }
        while (c < 0) {
            c += 65537;
        }
        return (short) (c & 0xFFFF);
    }

    private short[] algorithm(short[] keys, short[] input, boolean encode, long initializeVector) {
        short[] copyInput = new short[input.length];
        System.arraycopy(input, 0, copyInput, 0, input.length);
        for (int i = 0; i < copyInput.length; i += 4) {
            if (encode && enabledCFB) {
                if (i == 0) {
                    copyInput[i] ^= (short) ((initializeVector >> 48) & 0xFFFF);
                    copyInput[i + 1] ^= (short) ((initializeVector >> 32) & 0xFFFF);
                    copyInput[i + 2] ^= (short) ((initializeVector >> 16) & 0xFFFF);
                    copyInput[i + 3] ^= (short) (initializeVector & 0xFFFF);
                } else {
                    copyInput[i] ^= copyInput[i - 4];
                    copyInput[i + 1] ^= copyInput[i - 3];
                    copyInput[i + 2] ^= copyInput[i - 2];
                    copyInput[i + 3] ^= copyInput[i - 1];
                }
            }
            for (int j = 0; j < 8; j++) {
                copyInput[i] = multiplyMod65537(keys[6 * j], copyInput[i]);
                copyInput[i + 1] += keys[6 * j + 1];
                copyInput[i + 2] += keys[6 * j + 2];
                copyInput[i + 3] = multiplyMod65537(keys[6 * j + 3], copyInput[i + 3]);
                short helper1 = (short) ((copyInput[i] ^ copyInput[i + 2]) & 0xFFFF);
                short helper2 = (short) ((copyInput[i + 1] ^ copyInput[i + 3]) & 0xFFFF);
                helper1 = multiplyMod65537(helper1, keys[6 * j + 4]);
                helper2 += helper1;
                helper2 = multiplyMod65537(helper2, keys[6 * j + 5]);
                helper1 += helper2;
                copyInput[i] ^= helper2;
                copyInput[i + 2] ^= helper2;
                copyInput[i + 1] ^= helper1;
                copyInput[i + 3] ^= helper1;
                short helper3 = copyInput[i + 1];
                copyInput[i + 1] = copyInput[i + 2];
                copyInput[i + 2] = helper3;
            }
            copyInput[i] = multiplyMod65537(keys[48], copyInput[i]);
            short helper3 = copyInput[i + 1];
            copyInput[i + 1] = copyInput[i + 2];
            copyInput[i + 2] = helper3;
            copyInput[i + 1] += keys[49];
            copyInput[i + 2] += keys[50];
            copyInput[i + 3] = multiplyMod65537(keys[51], copyInput[i + 3]);
        }
        if (!encode && enabledCFB) {
            long initVectorDecode = 0;
            for (int i = copyInput.length - 1; i >= 3; i -= 4) {
                if (i == 3) {
                    copyInput[i] ^= (short) (initVectorDecode & 0xFFFF);
                    copyInput[i - 1] ^= (short) ((initVectorDecode >> 16) & 0xFFFF);
                    copyInput[i - 2] ^= (short) ((initVectorDecode >> 32) & 0xFFFF);
                    copyInput[i - 3] ^= (short) ((initVectorDecode >> 48) & 0xFFFF);
                } else {
                    copyInput[i] ^= input[i - 4];
                    copyInput[i - 1] ^= input[i - 5];
                    copyInput[i - 2] ^= input[i - 6];
                    copyInput[i - 3] ^= input[i - 7];
                }
                if (i == copyInput.length - 1) {
                    initVectorDecode = (copyInput[i] & 0xFFFF);
                    initVectorDecode |= (((long) copyInput[i - 1] & 0xFFFF) << 16);
                    initVectorDecode |= (((long) copyInput[i - 2] & 0xFFFF) << 32);
                    initVectorDecode |= (((long) copyInput[i - 3] & 0xFFFF) << 48);
                }
            }
        }
        return copyInput;
    }

    private static short[] cycleMoveLeft25(short[] bytesInput) {
        short[] bytes = new short[bytesInput.length];
        short lastOne = bytesInput[0];
        System.arraycopy(bytesInput, 1, bytes, 0, bytes.length - 1);
        bytes[bytes.length - 1] = lastOne;
        short lastRemainder = (short) (((bytes[0]) >> 7 & 0x1FF));
        for (int i = 0; i < bytes.length - 1; i++) {
            short nextRemainder = (short) (((bytes[i + 1]) >> 7 & 0x1FF));
            bytes[i] <<= 9;
            bytes[i] &= (short) 0xFE00;
            bytes[i] |= nextRemainder;
        }
        bytes[bytes.length - 1] <<= 9;
        bytes[bytes.length - 1] &= (short) 0xFE00;
        bytes[bytes.length - 1] |= lastRemainder;
        return bytes;
    }

    private static short[] generateKeys(short[] key) {
        short[] copyKey = new short[key.length];
        System.arraycopy(key, 0, copyKey, 0, key.length);
        short[] keys = new short[52];
        for (int i = 0; i < 52; i++) {
            keys[i] = copyKey[i % 8];
            if ((i + 1) % 8 == 0) {
                copyKey = cycleMoveLeft25(copyKey);
            }
        }
        return keys;
    }

    private static short[] generateReversedKeys(short[] key) {
        short[] copyKey = generateKeys(key);
        short[] result = new short[52];
        for (int i = 0; i < 8; i++) {
            result[i * 6] = extendedEuqlid(copyKey[(8 - i) * 6]);
            if (i == 0) {
                result[1] = (short) -copyKey[49];
                result[2] = (short) -copyKey[50];
            } else {

                result[i * 6 + 1] = (short) -copyKey[(8 - i) * 6 + 2];
                result[i * 6 + 2] = (short) -copyKey[(8 - i) * 6 + 1];
            }
            result[i * 6 + 3] = extendedEuqlid(copyKey[(8 - i) * 6 + 3]);
            result[i * 6 + 4] = copyKey[(7 - i) * 6 + 4];
            result[i * 6 + 5] = copyKey[(7 - i) * 6 + 5];
        }
        result[48] = extendedEuqlid(copyKey[0]);
        result[49] = (short) -copyKey[1];
        result[50] = (short) -copyKey[2];
        result[51] = extendedEuqlid(copyKey[3]);
        return result;
    }

    //ax + by = GCD(a,b)
    public static short extendedEuqlid(int a) {
        a = a & 0xFFFF;
        if (a == 0) return 0;
        int rI = a;
        int sI = 1;
        int tI = 0;
        int rIPlus1 = 65537;
        int sIPlus1 = 0;
        int tIPlus1 = 1;

        while (rIPlus1 != 0) {
            int quotient = rI / rIPlus1;
            int temp = rIPlus1;
            rIPlus1 = rI - quotient * rIPlus1;
            rI = temp;

            temp = sIPlus1;
            sIPlus1 = sI - quotient * sIPlus1;
            sI = temp;

            temp = tIPlus1;
            tIPlus1 = tI - quotient * tIPlus1;
            tI = temp;
        }
        if (sI < 0) sI += 65537;
        return (short) sI;
    }
}

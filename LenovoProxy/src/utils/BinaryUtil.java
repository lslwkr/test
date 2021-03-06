package utils;

import java.util.*;



public abstract class BinaryUtil
{
    private static final byte[] EMPTY_BINARY = {};

    public static byte[] getBinary()
    {
        return EMPTY_BINARY;
    }

    public static byte[] getBinary(List<Byte> list)
    {
        int n = list.size(), i = 0;
        byte[] bytes = new byte[n];
        for (Byte b : list)
        {
            bytes[i++] = b;
        }
        return bytes;
    }

    public static byte[] getBinary(String string)
    {
        return fromStringBase16(string, 0, string.length());
    }

    public static byte[] getNullableBinary(String string)
    {
        return string == null ? null : fromStringBase16(string);
    }
    
    public static byte[] getNullableBinaryBase64(String string)
    {
        return string == null ? null : fromStringBase64(string);
    }
    
    public static byte[] getBinaryBase64(String string)
    {
        return fromStringBase64(string);
    }

    public static boolean equal(byte[] a, byte[] b)
    {
        if (a == null || b == null)
        {
            return false;
        }
        else
        {
            return Arrays.equals(a, b);
        }
    }

    public static boolean notEqual(byte[] a, byte[] b)
    {
        if (a == null || b == null)
        {
            return false;
        }
        else
        {
            return ! Arrays.equals(a, b);
        }
    }

    // -----------------------------------------------------------------------
    // base 16 conversions
    // -----------------------------------------------------------------------

    /**
     ** Convert from hexadecimal string to byte array.
     **/
    public static byte[] fromStringBase16(String string)
    {
        return fromStringBase16(string, 0, string.length());
    }

    /**
     ** Convert from hexadecimal string to byte array.
     **/
    public static byte[] fromStringBase16(String string, int offset, int length)
    {
        byte[] bytes = new byte[length / 2];
        for (int j = 0, k = 0; k < length; j++, k += 2)
        {
            int hi = Character.digit(string.charAt(offset + k), 16);
            int lo = Character.digit(string.charAt(offset + k + 1), 16);
            if (hi == -1 || lo == -1)
            {
                throw new IllegalArgumentException(string);
            }
            bytes[j] = (byte)(16 * hi + lo);
        }
        return bytes;
    }

    /**
     ** Convert from byte array to hexadecimal string.
     **/
    public static String toStringBase16(byte[] bytes)
    {
        return toStringBase16(bytes, 0, bytes.length);
    }

    /**
     ** Convert from byte array to hexadecimal string.
     **/
    public static String toStringBase16(byte[] bytes, int offset, int length)
    {
        char[] chars = new char[length * 2];
        for (int j = 0, k = 0; j < length; j++, k += 2)
        {
            int value = (bytes[offset + j] + 256) & 255;
            chars[k] = Character.forDigit(value >> 4, 16);
            chars[k + 1] = Character.forDigit(value & 15, 16);
        }
        return new String(chars);
    }

    // -----------------------------------------------------------------------
    // base 64 conversions
    // -----------------------------------------------------------------------

    private static final int  BASELENGTH         = 255;
    private static final int  LOOKUPLENGTH       = 64;
    private static final int  TWENTYFOURBITGROUP = 24;
    private static final int  EIGHTBIT           = 8;
    private static final int  SIXTEENBIT         = 16;
    private static final int  FOURBYTE           = 4;
    private static final int  SIGN               = -128;
    private static final char PAD                = '=';
    private static final byte NOT_DATA           = -1;

    private static final byte[] base64Alphabet       = new byte[BASELENGTH];
    private static final char[] lookUpBase64Alphabet = new char[LOOKUPLENGTH];

    static
    {
        for (int i = 0; i < BASELENGTH; i++)
        {
            base64Alphabet[i] = NOT_DATA;
        }
        for (int i = 'Z'; i >= 'A'; i--)
        {
            base64Alphabet[i] = (byte)(i - 'A');
        }
        for (int i = 'z'; i >= 'a'; i--)
        {
            base64Alphabet[i] = (byte)(i - 'a' + 26);
        }
        for (int i = '9'; i >= '0'; i--)
        {
            base64Alphabet[i] = (byte)(i - '0' + 52);
        }
        base64Alphabet['+'] = 62;
        base64Alphabet['/'] = 63;
        for (int i = 0; i <= 25; i++)
        {
            lookUpBase64Alphabet[i] = (char)('A' + i);
        }
        for (int i = 26, j = 0; i <= 51; i++, j++)
        {
            lookUpBase64Alphabet[i] = (char)('a' + j);
        }
        for (int i = 52, j = 0; i <= 61; i++, j++)
        {
            lookUpBase64Alphabet[i] = (char)('0' + j);
        }
        lookUpBase64Alphabet[62] = '+';
        lookUpBase64Alphabet[63] = '/';
    }

    /**
     ** Convert from byte array to base 64 encoded string.
     **/
    public static String toStringBase64(byte[] bytes)
    {
        if (bytes == null)
        {
	        return null;
        }
	    return toStringBase64(bytes, 0, bytes.length);
    }

    public static String toStringBase64(byte[] bytes, boolean wrap)
    {
        return toStringBase64(bytes, 0, bytes.length, wrap);
    }

    public static String toStringBase64(byte[] bytes, int offset, int length)
    {
        return toStringBase64(bytes, offset, length, false);
    }

    public static String toStringBase64(byte[] bytes, int offset, int length, boolean wrap)
    {
        StringBuffer s = new StringBuffer((length * 4) / 3 + 1);
        int n = offset + length, lineSize = 0;
        for (int i = offset; i < n; i += 3)
        {
            if (wrap)
            {
                if (lineSize >= 76)
                {
                    // Must have at most 76 characters per line.
                    s.append('\n');
                    lineSize = 0;
                }
            }
            int value;
            int chars;
            if (i < n - 2)
            {
                value = (0x00FF0000 & (bytes[i] << 16))
                    | (0x0000FF00 & (bytes[i + 1] << 8))
                    | (0x000000FF & bytes[i + 2]);
                chars = 4;
            }
            else if (i < n - 1)
            {
                value = (0x00FF0000 & (bytes[i] << 16))
                    | (0x0000FF00 & (bytes[i + 1] << 8));
                chars = 3;
            }
            else
            {
                value = (0x00FF0000 & (bytes[i] << 16));
                chars = 2;
            }
            while (chars-- > 0)
            {
                int x = (0x00FC0000 & value) >> 18;
                char c = getCharBase64(x);
                s.append(c);
                lineSize += 1;
                value = value << 6;
            }
            if (i == n - 1)
            {
                s.append("==");
                lineSize += 2;
            }
            else if (i == n - 2)
            {
                s.append('=');
                lineSize += 1;
            }
        }
        return s.toString();
    }

    /**
     ** Convert from byte array to base 64 encoded string.
     ** Code adapted from apache xml security project.
     **/
    public static byte[] fromStringBase64(String base64String)
    {
        char[] base64Chars = base64String.trim().toCharArray();
        int len = base64Chars.length;
        if (len % FOURBYTE != 0)
        {
            throw new IllegalArgumentException("base64.decode: string length should be divisible by four");
        }
        int numberQuadruple = (len / FOURBYTE);
        if (numberQuadruple == 0)
        {
            return new byte[0];
        }
        byte[] decodedData = null;
        byte b1 = 0, b2 = 0, b3 = 0, b4 = 0;
        byte d1 = 0, d2 = 0, d3 = 0, d4 = 0;
        int i = 0;
        int encodedIndex = 0;
        int dataIndex    = 0;
        dataIndex = (numberQuadruple - 1) * 4;
        encodedIndex = (numberQuadruple - 1) * 3;
        if (! isData((d1 = (byte)base64Chars[dataIndex++]))
            || ! isData((d2 = (byte)base64Chars[dataIndex++])))
        {
            throw new IllegalArgumentException("base64.decode");
        }
        b1 = base64Alphabet[d1];
        b2 = base64Alphabet[d2];
        d3 = (byte)base64Chars[dataIndex++];
        d4 = (byte)base64Chars[dataIndex++];
        if (! isData(d3)
            || ! isData(d4))
        {
            // Check if they are PAD characters
            if (isPad(d3) && isPad(d4))
            {
                // Two PAD e.g. 3c[Pad][Pad]
                if ((b2 & 0xf) != 0) //last 4 bits should be zero
                {
                    throw new IllegalArgumentException("base64.decode");
                }
                decodedData = new byte[encodedIndex + 1];
                decodedData[encodedIndex] = (byte)(b1 << 2 | b2 >> 4) ;
            }
            else if (!isPad(d3) && isPad(d4))
            {
                // One PAD e.g. 3cQ[Pad]
                b3 = base64Alphabet[d3];
                if ((b3 & 0x3) != 0) //last 2 bits should be zero
                {
                    throw new IllegalArgumentException("base64.decode");
                }
                decodedData = new byte[encodedIndex + 2];
                decodedData[encodedIndex++] = (byte)(b1 << 2 | b2 >> 4);
                decodedData[encodedIndex] = (byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
            }
            else
            {
                throw new IllegalArgumentException("base64.decode"); // an error like "3c[Pad]r", "3cdX", "3cXd", "3cXX" where X is non data
            }
        }
        else
        {
            // No PAD e.g 3cQl
            decodedData = new byte[encodedIndex + 3];
            b3 = base64Alphabet[d3];
            b4 = base64Alphabet[d4];
            decodedData[encodedIndex++] = (byte)(b1 << 2 | b2 >> 4) ;
            decodedData[encodedIndex++] = (byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
            decodedData[encodedIndex++] = (byte)(b3 << 6 | b4);
        }
        encodedIndex = 0;
        dataIndex = 0;
        for (; i < numberQuadruple - 1; i++)
        {
            if (! isData((d1 = (byte)base64Chars[dataIndex++]))
                || ! isData((d2 = (byte)base64Chars[dataIndex++]))
                || ! isData((d3 = (byte)base64Chars[dataIndex++]))
                || ! isData((d4 = (byte)base64Chars[dataIndex++])))
            {
                throw new IllegalArgumentException("base64.decode");
            }
            b1 = base64Alphabet[d1];
            b2 = base64Alphabet[d2];
            b3 = base64Alphabet[d3];
            b4 = base64Alphabet[d4];
            decodedData[encodedIndex++] = (byte)(b1 << 2 | b2 >> 4) ;
            decodedData[encodedIndex++] = (byte)(((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
            decodedData[encodedIndex++] = (byte)(b3 << 6 | b4);
        }
        return decodedData;
    }

    private static char getCharBase64(int c)
    {
        if (c < 26)
        {
            return (char)('A' + c);
        }
        else if (c < 52)
        {
            return (char)('a' + (c - 26));
        }
        else if (c < 62)
        {
            return (char)('0' + (c - 52));
        }
        else if (c == 62)
        {
            return '+';
        }
        else // c == 63
        {
            return '/';
        }
    }

    private static final boolean isPad(byte octet)
    {
        return (octet == PAD);
    }

    private static final boolean isData(byte octet)
    {
        return (base64Alphabet[octet] != NOT_DATA);
    }

//    public static byte[] concat(BinaryList binList) {
//        int n = 0;
//        int nb = binList.size();
//        for (int i = 0; i < nb; i++)
//        {
//            byte[] b = binList.get(i);
//            n += b.length;
//        }
//        byte[] bytes = new byte[n];
//        int offset = 0;
//        for (int i = 0; i < nb; i++)
//        {
//            byte[] b = binList.get(i);
//            int k = b.length;
//            System.arraycopy(b, 0, bytes, offset, k);
//            offset += k;
//        }
//        return bytes;
//    }
	
    public static byte[] slice(byte[] bytes, int start)
    {
        return slice(bytes, start, bytes.length);
    }

    public static byte[] slice(byte[] bytes, int start, int end)
    {
        int n = bytes.length;
        int length = (end < 0) ? (n + end) : (end - start);
        byte[] newBytes = new byte[length];
        System.arraycopy(bytes, start, newBytes, 0, length);
        return newBytes;
    }

    // For XScript overloading
    public static byte[] slice2(byte[] bytes, int start, int end)
    {
        return slice(bytes, start, end);
    }
}


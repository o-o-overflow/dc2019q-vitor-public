import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


class Cryptor {

    private static final byte[] initVector = {
        (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
        (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
        (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
        (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37
    };

    public static void main(String... args) {
        System.out.println("encrypting " + args[0] + " => " + args[1] + " with key " + args[2]);
        System.out.println(encrypt(args[0], args[1], args[2]));
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(in);
        return md.digest();
    }

    public static String encrypt(String ptFp, String ctFp, String key) {

        try {
            byte[] K0 = hexStringToByteArray(key);
            byte[] keyBytes = hash(K0);

            File ptFile = new File(ptFp);
            File ctFile = new File(ctFp);
            byte[] pt = Files.readAllBytes(ptFile.toPath());

            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] ct = cipher.doFinal(pt);

            OutputStream out = new FileOutputStream(ctFile);
            out.write(ct, 0, ct.length);
            out.flush();
            out.close();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}

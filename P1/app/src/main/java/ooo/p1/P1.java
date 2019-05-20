package ooo.p1;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class P1 {

    public static String abc = "smnvlwkuelqkjsmxzz"; //p2fntemplate
    public static String def = "mmdffuoscjdamcnssn"; // p2encfn
    public static String ghi = "xtszswemcwohpluqmi"; // p3encfn

    public static boolean cf(Context ctx, String f) {

//        Log.e("OOO", "P1:cf");

        try {
            // get K1
            byte[] K1 = g1(f.substring(4, 44));

            // retrieve p2enc
            cfa(ctx, def);
            cfa(ctx, ghi);
            File qqqq = new File(ctx.getFilesDir(), def);

            // decrypt p2. this creates libp2.so
            dp2(ctx, qqqq, K1);

            // load p2
//            Log.e("OOO", "About to load p2");
            // TODO p2lib
            System.loadLibrary(abc);
//            Log.e("OOO", "Done loading p2");

            // execute p2 payload

            File filesDir = ctx.getFilesDir();
            String tre = (new P1()).xxx(f, filesDir.getAbsolutePath());
            if (tre == null) {
//                Log.e("OOO", "Something went wrong in the JNI part");
                return false;
            }
//            Log.e("OOO", "p5 file path: " + p5fp);

            // at this point, p5 should be available (it's decrypted by p4)

            // try to load p5.apk
            File ii = new File(tre);

            // make sure the file exists
            if (!ii.isFile()) {
//                Log.e("OOO", "p5.apk NOT found");
                return false;
            }

            return true;
        } catch(Exception e) {
//            Log.e("OOO", "Something went wrong (p1:cf): " + Log.getStackTraceString(e));
        }

        return false;
    }

    public static byte[] g1(String f) {
        byte[] K1 = new byte[4];
        byte[] fb = f.getBytes();
        int i, j;
        for (j=0; j<4; j++) {
            K1[j] = 0;
        }
        // take only even blocks
        for (i=0; i<10; i+=2) {
            for (j=0; j<4; j++) {
                K1[j] ^= fb[4*(i+1)+j];
            }
        }
//        Log.e("OOO", "K1: " + String.format("%02x%02x%02x%02x", K1[0], K1[1], K1[2], K1[3]));
        return K1;
    }


    private static void cff(File src, File dst) throws Exception {
        InputStream in = new FileInputStream(src);
        OutputStream out = new FileOutputStream(dst);

        byte[] buffer = new byte[1024];
        int read;
        while((read = in.read(buffer)) != -1){
            out.write(buffer, 0, read);
        }
        in.close();
        out.close();
    }


    public static byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(in);
        return md.digest();
    }


    private static final byte[] ooo = {
            (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
            (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
            (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
            (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37
    };

    private static File dp2(Context ctx, File p2Enc, byte[] K1) throws Exception {
//        Log.e("OOO", "decrypting p2");

        byte[] enckey = hash(K1);
        byte[] ct = Files.readAllBytes(p2Enc.toPath());

        try {
            IvParameterSpec iv = new IvParameterSpec(ooo);
            SecretKeySpec skeySpec = new SecretKeySpec(enckey, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] pt = cipher.doFinal(ct);

            File p2file = new File(ctx.getFilesDir(), "lib" + abc + ".so");
            OutputStream out = new FileOutputStream(p2file);
            out.write(pt, 0, pt.length);
            out.flush();
            out.close();

            return p2file;
        } catch (Exception e) {
//            Log.e("OOO", "Exception while decrypting p2:" + Log.getStackTraceString(e));
        }
        return null;
    }

    // copy from assets to files. Returns then new file path
    private static File cfa(Context ctx, String fileName) throws Exception {
//        Log.e("OOO", "cfa " + fileName);

        AssetManager assetManager = ctx.getAssets();

        InputStream in = assetManager.open(fileName);
        File outFile = new File(ctx.getFilesDir().getAbsolutePath(), fileName);
        OutputStream out = new FileOutputStream(outFile);
        byte[] buffer = new byte[1024];
        int read;
        while((read = in.read(buffer)) != -1){
            out.write(buffer, 0, read);
        }
        in.close();
        out.close();

        return outFile;
    }

    private native String xxx(String flag, String filesDir);
}
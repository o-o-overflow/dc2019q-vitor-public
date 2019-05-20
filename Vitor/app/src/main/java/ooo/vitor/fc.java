package ooo.vitor;

import android.content.Context;
import android.content.res.AssetManager;
import android.net.Uri;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dalvik.system.DexClassLoader;

public class fc {

    public static String p1Fn = "nsavlkureaasdqwecz";
    public static String p1EncFn = "ckxalskuaewlkszdva";
    public static String p5EncFn = "cxnvhaekljlkjxxqkq";
    public static String randEncFn = "zslzrfomygfttivyac";
    public static String rand2EncFn = "fwswzofqwkzhsgdxfr";

    public static boolean mValid = false;

    // checkFlag
    public static boolean cf(MainActivity ma, String flag) {
        try {
            cfa(ma, p1EncFn); // P1
            cfa(ma, p5EncFn); // P5 JS
            cfa(ma, randEncFn); // random
            cfa(ma, rand2EncFn); // random

            // basic checks on the flag
            if ((!flag.startsWith("OOO{")) || (!flag.endsWith("}")) || (flag.length() != 45)) {
                // flag not valid
                return false;
            }

            // get K0
            byte[] K0 = g0(flag.substring(4, 44));

            // retrieve p1enc
            File trrtww = new File(ma.getFilesDir(), p1EncFn);

            // decrypt p1enc
            File p1 = dp1(ma, trrtww, K0);

            boolean res = false;
            res = cf(ma, p1, flag);
            if (!res) return false;

            File uyr = new File(ma.getFilesDir(), "bam.html");
            if (uyr == null && !uyr.isFile()) {
                return false;
            }
            ma.mWebView.loadUrl("file:///" + uyr.getAbsolutePath() + "?flag=" + Uri.encode(flag));

            return mValid;
        } catch(Exception e) {
//            Log.e("OOO", "Something went wrong (p0:cf): " + Log.getStackTraceString(e));
        }

        return false;
    }

    // getKey0
    public static byte[] g0(String f) {
        byte[] K0 = new byte[4];
        byte[] fb = f.getBytes();
        int i, j;
        for (j=0; j<4; j++) {
            K0[j] = 0;
        }
        for (i=0; i<10; i++) {
            for (j=0; j<4; j++) {
                K0[j] ^= fb[4*i+j];
            }
        }
//        Log.e("OOO", "K0: " + String.format("%02x%02x%02x%02x", K0[0], K0[1], K0[2], K0[3]));
        return K0;
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

    private static void copyFile(File src, File dst) throws Exception {
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


    private static final byte[] initVector = {
            (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
            (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
            (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37,
            (byte)0x13, (byte)0x37, (byte)0x13, (byte)0x37
    };

    private static File dp1(Context ctx, File p1Enc, byte[] K0) throws Exception {
//        Log.e("OOO", "decrypting p1");

        byte[] enckey = hash(K0);
        byte[] ct = Files.readAllBytes(p1Enc.toPath());

        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(enckey, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] pt = cipher.doFinal(ct);

            File pee = new File(ctx.getFilesDir(), p1Fn);
            OutputStream out = new FileOutputStream(pee);
            out.write(pt, 0, pt.length);
            out.flush();
            out.close();

            return pee;
        } catch (Exception e) {
//            Log.e("OOO", "Exception while decrypting p1:" + Log.getStackTraceString(e));
        }
        return null;
    }


    // load DEX from path
    // checkflag
    private static boolean cf(Context ctx, File p1, String flag) {
        // this is the dex
//        Log.e("OOO", "Loading p1: " + p1.getAbsolutePath());

        File filesDir = new File(ctx.getFilesDir().getAbsolutePath());

        // get class loader
        DexClassLoader classloader = new DexClassLoader(
            p1.getAbsolutePath(), filesDir.getAbsolutePath(),
            filesDir.getAbsolutePath(), // path for native libs
            ClassLoader.getSystemClassLoader());

        // load it and call it
        boolean res = false;
        try {
            Class<?> classToLoad = classloader.loadClass("ooo.p1.P1");
            Method method = classToLoad.getDeclaredMethod("cf", Context.class, String.class);
            res = (boolean) method.invoke(classToLoad, ctx, flag);
        } catch (Exception e) {
//            Log.e("OOO", "Exception while checking flags:" + Log.getStackTraceString(e));
        }
        return res;
    }
}

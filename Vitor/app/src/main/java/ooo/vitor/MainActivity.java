package ooo.vitor;

import android.graphics.drawable.Drawable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;

public class MainActivity extends AppCompatActivity {

    TextView mResultWidget = null;
    WebView mWebView = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final EditText flagWidget = findViewById(R.id.flag);
        final ImageView qrcodeWidget = findViewById(R.id.qrcode);
        final Button checkFlag = findViewById(R.id.checkflag);
        final TextView resultWidget = findViewById(R.id.result);
        final WebView wv = findViewById(R.id.webview);
        mResultWidget = resultWidget;
        mWebView = wv;

        wv.getSettings().setJavaScriptEnabled(true);
        wv.addJavascriptInterface(this, "JSInterface");

        try
        {
            // get input stream
            InputStream ims = getAssets().open("qrcode.png");
            // load image as Drawable
            Drawable d = Drawable.createFromStream(ims, null);
            // set image to ImageView
            qrcodeWidget.setImageDrawable(d);
            ims.close();
        }
        catch(IOException ex)
        {
            Log.e("OOO", "failed to load qrcode");
        }

        flagWidget.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                mResultWidget.setText("");
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        checkFlag.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                resultWidget.setText("Checking...");
                resultWidget.setTextColor(0xffffa500);
                final String flag = flagWidget.getText().toString();

                // wait 1 second before killing
                fc.cf(MainActivity.this, flag);

                try {
                    Thread t;
                    // wait 2 seconds before updating the UI
                    t = new Thread() {
                        public void run() {
                            try {
                                Thread.sleep(2000);
                            } catch (Exception e) {
                            }
                            updateFlagWidget();
                        }
                    };
                    t.start();

                    // wait few seconds before killing
                    t = new Thread() {
                        public void run() {
                            try {
                                Thread.sleep(10000);
                            } catch (Exception e) {
                                // pass
                            }

                            MainActivity.this.finishAndRemoveTask();
                            System.exit(0);
                        }
                    };
                    t.start();
                } catch (Exception e) {
                    Log.e("OOO", "Exception:" + Log.getStackTraceString(e));
                }
            }
        });
    }

    public void updateFlagWidget() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                String msg;
                int color;
                if (fc.mValid) {
                    Log.e("OOO", "Flag is valid!");
                    msg = "Valid flag!";
                    color = 0xff009b00;
                } else {
                    msg = "Invalid flag";
                    Log.e("OOO", "Flag is not valid dude");
                    color = 0xffff0000;
                }
                mResultWidget.setText(msg);
                mResultWidget.setTextColor(color);
            }
        });
    }

    @JavascriptInterface
    public void setFlagAsValid() {
        try {
            fc.mValid = true;
        } catch (Exception e) {
            Log.e("OOO", "Exception while setting flag as valid:" + Log.getStackTraceString(e));
        }
    }
}

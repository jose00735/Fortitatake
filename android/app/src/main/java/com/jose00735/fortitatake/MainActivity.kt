package com.jose00735.fortitatake

import android.annotation.SuppressLint
import android.content.ContentValues
import android.os.Bundle
import android.provider.MediaStore
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    private lateinit var web: WebView
    private var loadedUrl: String? = null

    private val scanner = registerForActivityResult(ScanContract()) { r ->
        deliver("FT_onScan", r.contents ?: "")
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this).apply {
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            setBackgroundColor(0xFF0E0C0B.toInt())
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.mediaPlaybackRequiresUserGesture = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            webViewClient = object : WebViewClient() {
                // Stay inside the app's own engine; anything else is refused.
                override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest): Boolean =
                    req.url.host != "127.0.0.1"
            }
            addJavascriptInterface(Bridge(), "FTAndroid")
        }
        setContentView(web)
        splash("Starting FortiTatake…")
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (web.canGoBack()) web.goBack() else finish()
            }
        })
        boot()
    }

    override fun onResume() {
        super.onResume()
        if (loadedUrl != null && Engine.url == null) boot() // the engine was stopped while we were away
    }

    override fun onDestroy() {
        if (isFinishing) Engine.stop()
        web.destroy()
        super.onDestroy()
    }

    private fun boot() {
        Engine.start(this) { url, error ->
            runOnUiThread {
                if (url != null) {
                    if (url != loadedUrl) {
                        loadedUrl = url
                        web.clearHistory()
                        web.loadUrl(url)
                    }
                } else {
                    splash("FortiTatake couldn't start.<br><br><small>${escape(error ?: "")}</small>")
                }
            }
        }
    }

    private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace("\n", "<br>")

    private fun splash(msg: String) {
        web.loadDataWithBaseURL(null,
            """<html><body style="margin:0;height:100vh;display:grid;place-items:center;background:#0e0c0b;color:#f2e9df;font:16px system-ui;text-align:center;padding:24px;box-sizing:border-box"><div>$msg</div></body></html>""",
            "text/html", "utf-8", null)
    }

    private fun deliver(fn: String, arg: String) = runOnUiThread {
        web.evaluateJavascript("window.$fn && window.$fn(${JSONObject.quote(arg)})", null)
    }

    /** Methods the web UI can call as window.FTAndroid.*. */
    inner class Bridge {
        @JavascriptInterface
        fun scanQr() = runOnUiThread {
            scanner.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt("Scan the QR code on your PC: Settings → Sync → Pair a phone")
                    .setBeepEnabled(false)
                    .setOrientationLocked(false)
            )
        }

        @JavascriptInterface
        fun discover(ms: Int) {
            Discovery.find(this@MainActivity, ms.coerceIn(1000, 10000)) { json -> deliver("FT_onDiscover", json) }
        }

        @JavascriptInterface
        fun saveFile(name: String, mime: String, text: String) {
            try {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, mime.ifBlank { "text/plain" })
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: throw IllegalStateException("no Downloads folder")
                contentResolver.openOutputStream(uri)!!.use { it.write(text.toByteArray()) }
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                contentResolver.update(uri, values, null, null)
                runOnUiThread { Toast.makeText(this@MainActivity, "Saved to Downloads: $name", Toast.LENGTH_LONG).show() }
            } catch (e: Exception) {
                runOnUiThread { Toast.makeText(this@MainActivity, "Couldn't save $name: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }
    }
}

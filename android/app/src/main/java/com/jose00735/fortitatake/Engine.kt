package com.jose00735.fortitatake

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.File
import kotlin.concurrent.thread

/**
 * Runs the FortiTatake Go engine (the same core as the Windows app) as a child process.
 * It ships as lib/<abi>/libfortitatake.so so Android installs it executable, serves the
 * web UI on 127.0.0.1 and syncs with the PC as an FTSP/1 spoke.
 */
object Engine {
    @Volatile var url: String? = null
        private set
    private var process: Process? = null
    private val log = ArrayDeque<String>()

    fun recentLog(): String = synchronized(log) { log.joinToString("\n") }

    private fun deviceName(ctx: Context): String {
        val n = Settings.Global.getString(ctx.contentResolver, Settings.Global.DEVICE_NAME)
        return if (!n.isNullOrBlank()) n else "${Build.MANUFACTURER} ${Build.MODEL}".trim()
    }

    /** Starts the engine if needed and calls back on a background thread with the URL or an error. */
    fun start(ctx: Context, done: (url: String?, error: String?) -> Unit) {
        val p = process
        val u = url
        if (p != null && p.isAlive && u != null) {
            done(u, null)
            return
        }
        val app = ctx.applicationContext
        thread(name = "ft-engine", isDaemon = true) {
            try {
                val bin = File(app.applicationInfo.nativeLibraryDir, "libfortitatake.so")
                if (!bin.exists()) {
                    done(null, "The engine is missing for this phone's processor (${Build.SUPPORTED_ABIS.joinToString()}).")
                    return@thread
                }
                val data = File(app.filesDir, "ft").apply { mkdirs() }
                val pb = ProcessBuilder(
                    bin.absolutePath, "-no-open", "-role", "spoke",
                    "-data", data.absolutePath, "-name", deviceName(app), "-port", "0",
                ).redirectErrorStream(true)
                pb.environment()["HOME"] = data.absolutePath
                pb.environment()["TMPDIR"] = app.cacheDir.absolutePath
                val proc = pb.start()
                process = proc
                var answered = false
                val watchdog = thread(isDaemon = true) {
                    try {
                        Thread.sleep(15000)
                        if (!answered) {
                            answered = true
                            done(null, "The engine didn't start in time.\n" + recentLog())
                        }
                    } catch (_: InterruptedException) {
                    }
                }
                proc.inputStream.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        synchronized(log) {
                            log.addLast(line)
                            while (log.size > 200) log.removeFirst()
                        }
                        val i = line.indexOf("listening on ")
                        if (i >= 0 && !answered) {
                            answered = true
                            watchdog.interrupt()
                            url = line.substring(i + "listening on ".length).trim()
                            done(url, null)
                        }
                    }
                }
                // Output ended: the engine exited.
                url = null
                if (!answered) {
                    answered = true
                    done(null, "The engine stopped (exit ${runCatching { proc.waitFor() }.getOrNull()}).\n" + recentLog())
                }
            } catch (e: Exception) {
                done(null, "Couldn't start the engine: ${e.message}")
            }
        }
    }

    fun stop() {
        process?.destroy()
        process = null
        url = null
    }
}

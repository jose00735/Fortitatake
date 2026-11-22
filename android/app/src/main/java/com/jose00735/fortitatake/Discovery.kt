package com.jose00735.fortitatake

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Finds FortiTatake PCs on the Wi-Fi (DNS-SD service _fortitatake._tcp) so the phone can
 * follow the PC when its address changes. Results: [{name, host, port, id}].
 */
object Discovery {
    private const val TYPE = "_fortitatake._tcp."

    @Suppress("DEPRECATION")
    fun find(ctx: Context, ms: Int, done: (String) -> Unit) {
        val nsd = ctx.getSystemService(NsdManager::class.java)
        val main = Handler(Looper.getMainLooper())
        val found = JSONArray()
        val queue = ArrayDeque<NsdServiceInfo>()
        val resolving = AtomicBoolean(false)
        val finished = AtomicBoolean(false)

        fun next() {
            if (finished.get() || resolving.get()) return
            val info = synchronized(queue) { queue.removeFirstOrNull() } ?: return
            resolving.set(true)
            nsd.resolveService(info, object : NsdManager.ResolveListener {
                override fun onResolveFailed(si: NsdServiceInfo, code: Int) {
                    resolving.set(false); main.post { next() }
                }

                override fun onServiceResolved(si: NsdServiceInfo) {
                    val host = si.host?.hostAddress
                    if (host != null && !host.contains(':')) {
                        val id = si.attributes["id"]?.let { String(it) } ?: ""
                        synchronized(found) {
                            found.put(JSONObject().put("name", si.serviceName).put("host", host).put("port", si.port).put("id", id))
                        }
                    }
                    resolving.set(false); main.post { next() }
                }
            })
        }

        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(t: String) {}
            override fun onDiscoveryStopped(t: String) {}
            override fun onStartDiscoveryFailed(t: String, code: Int) {}
            override fun onStopDiscoveryFailed(t: String, code: Int) {}
            override fun onServiceLost(si: NsdServiceInfo) {}
            override fun onServiceFound(si: NsdServiceInfo) {
                synchronized(queue) { queue.addLast(si) }
                main.post { next() }
            }
        }
        try {
            nsd.discoverServices(TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            done("[]")
            return
        }
        main.postDelayed({
            finished.set(true)
            runCatching { nsd.stopServiceDiscovery(listener) }
            done(synchronized(found) { found.toString() })
        }, ms.toLong())
    }
}

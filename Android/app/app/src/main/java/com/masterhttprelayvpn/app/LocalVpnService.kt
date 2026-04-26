package com.masterhttprelayvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class LocalVpnService : VpnService() {
    private var tunInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIF_CHANNEL_ID,
                "VPN Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Shows VPN connection status" }
            getSystemService(NotificationManager::class.java)
                ?.createNotificationChannel(channel)
        }
    }

    override fun onBind(intent: Intent): IBinder? {
        return super.onBind(intent)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val notification = buildNotification("Connecting…")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        NOTIF_ID, notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    )
                } else {
                    startForeground(NOTIF_ID, notification)
                }
                serviceScope.launch { connect(intent.getStringExtra(EXTRA_CONFIG_JSON).orEmpty()) }
            }
            ACTION_DISCONNECT -> serviceScope.launch { disconnect() }
        }
        return Service.START_STICKY
    }

    private fun buildNotification(text: String): Notification =
        NotificationCompat.Builder(this, NOTIF_CHANNEL_ID)
            .setContentTitle("MasterHttpRelayVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()

    private fun connect(configJson: String) {
        if (isRunning) {
            return
        }

        tunInterface = Builder()
            .setSession("MasterHttpRelayVPN")
            .addAddress("10.10.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .setBlocking(true)
            .establish()

        if (tunInterface == null) {
            Log.e(TAG, "Unable to establish TUN interface")
            GoBridge.stopProxy()
            stopSelf()
            return
        }

        GoBridge.registerProtector(object : GoBridge.ProtectCallback {
            override fun protect(socketFd: Int): Boolean {
                return this@LocalVpnService.protect(socketFd)
            }
        })

        val proxyStatus = GoBridge.startVpn(configJson, tunInterface!!.fd)
        if (proxyStatus.contains("\"status\":\"error\"")) {
            Log.e(TAG, "Go core failed to start: $proxyStatus")
            tunInterface?.close()
            tunInterface = null
            GoBridge.registerProtector(null)
            stopSelf()
            return
        }

        isRunning = true
        Log.i(TAG, "VPN connected. TUN FD handed to Go core for TCP bridging.")
    }

    private fun disconnect() {
        isRunning = false

        tunInterface?.close()
        tunInterface = null

        val status = GoBridge.stopProxy()
        Log.i(TAG, "Proxy stop status: $status")
        GoBridge.registerProtector(null)

        @Suppress("DEPRECATION")
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        disconnect()
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_CONNECT = "com.masterhttprelayvpn.app.action.CONNECT"
        const val ACTION_DISCONNECT = "com.masterhttprelayvpn.app.action.DISCONNECT"
        const val EXTRA_CONFIG_JSON = "config_json"

        @Volatile
        var isRunning: Boolean = false

        private const val TAG = "LocalVpnService"
        private const val NOTIF_CHANNEL_ID = "mastervpn_channel"
        private const val NOTIF_ID = 1
    }
}
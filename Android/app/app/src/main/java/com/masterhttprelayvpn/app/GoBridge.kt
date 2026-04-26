package com.masterhttprelayvpn.app

import com.masterhttprelayvpn.core.mastervpncore.Mastervpncore
import com.masterhttprelayvpn.core.mastervpncore.Protector

object GoBridge {
    interface ProtectCallback {
        fun protect(socketFd: Int): Boolean
    }

    fun registerProtector(callback: ProtectCallback?) {
        if (callback == null) {
            Mastervpncore.setProtector(null)
        } else {
            Mastervpncore.setProtector(object : Protector {
                override fun protect(socketFd: Int): Boolean {
                    return callback.protect(socketFd)
                }
            })
        }
    }

    fun startVpn(configJson: String, tunFd: Int): String {
        if (configJson.isBlank()) {
            return "{\"status\":\"error\",\"message\":\"empty proxy config\"}"
        }
        if (tunFd < 0) {
            return "{\"status\":\"error\",\"message\":\"invalid tun fd\"}"
        }
        return try {
            Mastervpncore.startVpn(configJson, tunFd)
        } catch (e: Exception) {
            "{\"status\":\"error\",\"message\":\"${e.message ?: "gomobile invocation failed"}\"}"
        }
    }

    fun stopProxy(): String {
        return try {
            Mastervpncore.stopProxy()
        } catch (e: Exception) {
            "{\"status\":\"error\",\"message\":\"${e.message ?: "gomobile invocation failed"}\"}"
        }
    }
}

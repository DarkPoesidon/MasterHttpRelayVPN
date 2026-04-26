package com.masterhttprelayvpn.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var statusView: TextView
    private lateinit var connectButton: Button
    private lateinit var deploymentIdInput: EditText
    private lateinit var authPasswordInput: EditText

    private val prefs by lazy {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusView = findViewById(R.id.statusText)
        connectButton = findViewById(R.id.connectButton)
        deploymentIdInput = findViewById(R.id.deploymentIdInput)
        authPasswordInput = findViewById(R.id.authPasswordInput)

        loadSavedInputs()

        connectButton.setOnClickListener {
            if (LocalVpnService.isRunning) {
                stopVpnService()
                updateUi()
            } else {
                val configJson = buildConfigJson() ?: return@setOnClickListener
                saveInputs()
                requestVpnPermissionAndConnect(configJson)
            }
        }

        updateUi()
    }

    override fun onResume() {
        super.onResume()
        updateUi()
    }

    private fun requestVpnPermissionAndConnect(configJson: String) {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingConfigJson = configJson
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnService(configJson)
            updateUi()
        }
    }

    private fun startVpnService(configJson: String) {
        statusView.text = getString(R.string.status_connecting)
        val intent = Intent(this, LocalVpnService::class.java).apply {
            action = LocalVpnService.ACTION_CONNECT
            putExtra(LocalVpnService.EXTRA_CONFIG_JSON, configJson)
        }
        startService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, LocalVpnService::class.java).apply {
            action = LocalVpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }

    private fun updateUi() {
        if (LocalVpnService.isRunning) {
            statusView.text = getString(R.string.status_connected)
            connectButton.text = getString(R.string.disconnect)
        } else {
            statusView.text = getString(R.string.status_disconnected)
            connectButton.text = getString(R.string.connect)
        }
    }

    private fun buildConfigJson(): String? {
        val deploymentId = deploymentIdInput.text.toString().trim()
        val authPassword = authPasswordInput.text.toString().trim()

        if (deploymentId.isEmpty() || authPassword.isEmpty()) {
            Toast.makeText(this, getString(R.string.missing_fields), Toast.LENGTH_SHORT).show()
            return null
        }

        val payload = JSONObject()
        payload.put("mode", "apps_script")
        payload.put("google_ip", "216.239.38.120")
        payload.put("front_domain", "www.google.com")
        payload.put("script_id", deploymentId)
        payload.put("auth_key", authPassword)
        payload.put("listen_host", "127.0.0.1")
        payload.put("listen_port", 8085)
        payload.put("dns_resolver", "8.8.8.8:53")
        return payload.toString()
    }

    private fun loadSavedInputs() {
        deploymentIdInput.setText(prefs.getString(KEY_DEPLOYMENT_ID, "") ?: "")
        authPasswordInput.setText(prefs.getString(KEY_AUTH_PASSWORD, "") ?: "")
    }

    private fun saveInputs() {
        prefs.edit()
            .putString(KEY_DEPLOYMENT_ID, deploymentIdInput.text.toString().trim())
            .putString(KEY_AUTH_PASSWORD, authPasswordInput.text.toString().trim())
            .apply()
    }

    private var pendingConfigJson: String? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val config = pendingConfigJson
        pendingConfigJson = null
        if (result.resultCode == Activity.RESULT_OK && config != null) {
            startVpnService(config)  // sets status to "Connecting" and starts service
        } else {
            updateUi()  // only reset UI if user denied
        }
    }

    companion object {
        private const val PREFS_NAME = "mastervpn_prefs"
        private const val KEY_DEPLOYMENT_ID = "deployment_id"
        private const val KEY_AUTH_PASSWORD = "auth_password"
    }
}
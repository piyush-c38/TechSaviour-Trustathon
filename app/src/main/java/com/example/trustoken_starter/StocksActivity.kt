package com.example.trustoken_starter

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class StocksActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_stocks)

        val isAuthenticated = intent.getBooleanExtra("AUTHENTICATED", false)
        if (!isAuthenticated) {
            Toast.makeText(this, "Access Denied! Trust Token required.", Toast.LENGTH_LONG).show()
            finish()
        }
    }
}

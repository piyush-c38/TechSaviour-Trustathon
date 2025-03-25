package com.example.trustoken_starter

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class StocksAndShares : AppCompatActivity() {

    private lateinit var btnViewPortfolio: Button
    private lateinit var btnBuySellStocks: Button

    private lateinit var edtStock1: EditText
    private lateinit var edtStock2: EditText
    private lateinit var edtStock3: EditText
    private lateinit var edtStock4: EditText
    private lateinit var edtStock5: EditText
    private lateinit var edtStock6: EditText
    private lateinit var edtStock7: EditText
    private lateinit var edtStock8: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_stocks)

        btnViewPortfolio = findViewById(R.id.btnViewPortfolio)
        btnBuySellStocks = findViewById(R.id.btnBuySellStocks)

        edtStock1 = findViewById(R.id.editTextText2)
        edtStock2 = findViewById(R.id.editTextText3)
        edtStock3 = findViewById(R.id.editTextText4)
        edtStock4 = findViewById(R.id.editTextText5)
        edtStock5 = findViewById(R.id.editTextText6)
        edtStock6 = findViewById(R.id.editTextText7)
        edtStock7 = findViewById(R.id.editTextText8)

        btnViewPortfolio.setOnClickListener {
            checkTokenAndProceed {
                // Navigate to Portfolio screen
                Toast.makeText(this, "Viewing Portfolio", Toast.LENGTH_SHORT).show()
                val intent = Intent(this, Portfolio::class.java)
                startActivity(intent)
            }
        }

        btnBuySellStocks.setOnClickListener {
            checkTokenAndProceed {
                // Navigate to Buy/Sell screen
                Toast.makeText(this, "Navigating to Buy/Sell Stocks", Toast.LENGTH_SHORT).show()
                val intent = Intent(this, BuySell::class.java)
                startActivity(intent)
            }
        }
    }

    private fun checkTokenAndProceed(action: () -> Unit) {
        val tokenDescriptor = detectSmartCard()
        if (tokenDescriptor != -1) {
            Toast.makeText(this, "Token detected! Proceeding.", Toast.LENGTH_SHORT).show()
            action() // Execute the action (navigation)
        } else {
            Toast.makeText(
                this,
                "No Token detected. Please insert the Trust Token.",
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    private fun detectSmartCard(): Int {
        val usbManager = getSystemService(Context.USB_SERVICE) as android.hardware.usb.UsbManager?
        usbManager?.deviceList?.values?.forEach { device ->
            if (device.vendorId == 10381 && device.productId == 64) {
                return usbManager.openDevice(device)?.fileDescriptor ?: -1
            }
        }
        return -1
    }
}

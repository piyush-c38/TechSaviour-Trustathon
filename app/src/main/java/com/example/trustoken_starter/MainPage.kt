package com.example.trustoken_starter

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainPage : AppCompatActivity() {

    private lateinit var btnBankingServices: Button
    private lateinit var btnStocksAndShares: Button
    private lateinit var edtBankingServiceName: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main_page)

        btnBankingServices = findViewById(R.id.button)
        btnStocksAndShares = findViewById(R.id.button2)
        edtBankingServiceName = findViewById(R.id.editTextText)

        btnBankingServices.setOnClickListener {
            val tokenDescriptor = TrusToken().detectSmartCard()
            if (tokenDescriptor != -1) {
                Toast.makeText(this, "Token detected! Proceeding to Banking Services.", Toast.LENGTH_SHORT).show()
                val intent = Intent(this, BankingServices::class.java)
                intent.putExtra("ServiceName", edtBankingServiceName.text.toString())
                startActivity(intent)
            } else {
                Toast.makeText(this, "No Token detected. Please insert the smart card.", Toast.LENGTH_SHORT).show()
            }
        }

        btnStocksAndShares.setOnClickListener {
            val intent = Intent(this, StocksAndShares::class.java)
            startActivity(intent)
        }
    }
}

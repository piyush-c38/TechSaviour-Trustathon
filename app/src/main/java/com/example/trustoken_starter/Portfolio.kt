package com.example.trustoken_starter

import android.os.Bundle
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class Portfolio : AppCompatActivity() {

    private lateinit var edtAccount: EditText
    private lateinit var edtEquityStatus: EditText
    private lateinit var edtName: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_portfolio)

        edtAccount = findViewById(R.id.editTextTextMultiLine)
        edtEquityStatus = findViewById(R.id.editTextTextMultiLine2)
        edtName = findViewById(R.id.editTextTextMultiLine3)

        fetchAndDisplayPortfolioData()
    }

    private fun fetchAndDisplayPortfolioData() {
        try {
            // Will fetch the encrypted data from server
            val encryptedAccount = "ENCRYPTED_ACCOUNT_DATA"
            val encryptedEquityStatus = "ENCRYPTED_EQUITY_STATUS_DATA"
            val encryptedName = "ENCRYPTED_NAME_DATA"

            // Decryptng the data using TrustToken
            val decryptedAccount = decrypt(encryptedAccount)
            val decryptedEquityStatus = decrypt(encryptedEquityStatus)
            val decryptedName = decrypt(encryptedName)
            edtAccount.setText("Account: $decryptedAccount")
            edtEquityStatus.setText("Equity Status: $decryptedEquityStatus")
            edtName.setText("Name: $decryptedName")
        } catch (e: Exception) {
            Toast.makeText(this, "Error fetching portfolio data: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
    external fun decrypt(string: String): String
}

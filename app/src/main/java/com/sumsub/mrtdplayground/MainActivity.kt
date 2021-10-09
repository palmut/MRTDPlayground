package com.sumsub.mrtdplayground

import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Surface
import androidx.compose.material.Text
import androidx.compose.material.TextField
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.sumsub.mrtdplayground.ui.theme.MRTDPlaygroundTheme

class MainActivity : ComponentActivity() {

    private val viewModel by viewModels<MainViewModel>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MRTDPlaygroundTheme {
                Surface(color = MaterialTheme.colors.background) {
                    MainScreen(viewModel = viewModel)
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()

        NfcAdapter.getDefaultAdapter(this)?.also { adapter ->
            val intent = Intent(applicationContext, this.javaClass).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            }

            val pendingIntent = PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            )
            adapter.enableForegroundDispatch(
                this,
                pendingIntent,
                null,
                arrayOf(arrayOf(IsoDepTechnologyTag))
            )
        }
    }

    override fun onPause() {
        super.onPause()
        NfcAdapter.getDefaultAdapter(this)?.disableForegroundDispatch(this@MainActivity)
    }

    override fun onNewIntent(intent: Intent?) {
        Log.d(TAG, "onNewIntent = $intent")
        super.onNewIntent(intent)

        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent?.action)) {
            val tag = intent?.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
            if (tag?.techList?.contains(IsoDepTechnologyTag) == true) {
                val isoDep = IsoDep.get(tag)
                viewModel.processMRTD(isoDep, assets)
            }
        }

    }

    companion object {
        private const val TAG = "MainActivity"
        private const val IsoDepTechnologyTag = "android.nfc.tech.IsoDep"
    }
}

@Composable
fun MainScreen(viewModel: MainViewModel) {
    Column {
        Spacer(modifier = Modifier.height(8.dp))
        InputField(
            label = "Passport number",
            text = viewModel.passportNumber.value,
            onTextChange = viewModel::changePasswordNumber
        )
        Spacer(modifier = Modifier.height(8.dp))
        InputField(
            label = "Birth date",
            text = viewModel.birthDate.value,
            onTextChange = viewModel::changeBirthDate
        )
        Spacer(modifier = Modifier.height(8.dp))
        InputField(
            label = "Expiration date",
            text = viewModel.expirationDate.value,
            onTextChange = viewModel::changeExpDate
        )
        Spacer(modifier = Modifier.height(8.dp))
        StatusMessage(message = viewModel.statusMessage.value)
        PassportItems(items = viewModel.passportItems)
    }
}

@Composable
fun PassportItems(items: List<MainViewModel.PassportRecordItem>) {
    val scrollState = rememberLazyListState()

    LazyColumn(
        state = scrollState,
    ) {
        items(items = items) { item ->
            when (item) {
                is MainViewModel.PassportRecordItem.TextItem -> TextPasswordItem(textItem = item)
                is MainViewModel.PassportRecordItem.ImageItem -> ImageItem(imageItem = item)
            }
        }
    }
}

@Composable
fun TextPasswordItem(textItem: MainViewModel.PassportRecordItem.TextItem) {
    Row(
        Modifier
            .padding(horizontal = 16.dp)
    ) {
        Text(
            modifier = Modifier.fillMaxWidth(fraction = 0.5f),
            text = textItem.label
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = textItem.value
        )
    }
}

@Composable
fun InputField(
    label: String,
    text: String,
    onTextChange: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = Modifier
            .padding(horizontal = 16.dp)
            .fillMaxWidth()
    ) {
        Text(
            modifier = Modifier
                .fillMaxWidth(fraction = 0.5f)
                .align(alignment = Alignment.CenterVertically)
            ,
            text = label
        )
        Spacer(modifier = Modifier.width(8.dp))
        TextField(
            value = text,
            onValueChange = onTextChange,
            modifier = modifier
        )
    }
}

@Composable
fun ImageItem(imageItem: MainViewModel.PassportRecordItem.ImageItem) {
    imageItem.image?.let {
        Box(
            modifier = Modifier.fillMaxWidth(),
            contentAlignment = Alignment.Center
        ) {
            Image(
                modifier = Modifier
                    .padding(16.dp),
                bitmap = it.asImageBitmap(),
                contentDescription = ""
            )
        }
    }
}

@Composable
fun StatusMessage(message: String) {
    Text(
        modifier = Modifier
            .padding(horizontal = 16.dp),
        text = message
    )
}

@Preview(showBackground = true)
@Composable
fun DefaultPreview() {
    MRTDPlaygroundTheme {

    }
}
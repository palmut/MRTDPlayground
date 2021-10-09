package com.sumsub.mrtdplayground

import android.content.res.AssetManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.nfc.tech.IsoDep
import android.util.Log
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.gemalto.jp2.JP2Decoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.sf.scuba.smartcards.CardService
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.x509.Certificate
import org.jmrtd.BACKey
import org.jmrtd.PassportService
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jnbis.internal.WsqDecoder
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.*

class MainViewModel : ViewModel() {

    val statusMessage = mutableStateOf("")
    val passportItems = mutableStateListOf<PassportRecordItem>()
    val passportNumber = mutableStateOf("")
    val expirationDate = mutableStateOf("")
    val birthDate = mutableStateOf("")

    fun processMRTD(tag: IsoDep, assets: AssetManager) {
        Log.d(TAG, "processMRTD: passportNumber = $passportNumber expirationDate=$expirationDate birthDate=$birthDate, tag=$tag")

        viewModelScope.launch {
            if (isValid(passportNumber.value, expirationDate.value, birthDate.value)) {
                passportItems.clear()
                statusMessage.value = "Authenticating..."
                val key = BACKey(passportNumber.value, birthDate.value, expirationDate.value)
                val cardService = CardService.getInstance(tag)
                val passportService = PassportService(cardService, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, PassportService.DEFAULT_MAX_BLOCKSIZE, false, false)
                passportService.open()

                val PACEPassed = tryPACE(passportService, key)
                statusMessage.value = "PACE passed = $PACEPassed"
                passportService.sendSelectApplet(PACEPassed)
                passportService.doBAC(key)
                val BACPassed = !PACEPassed && tryBAC(passportService, key)
                statusMessage.value = "BAC passed = $BACPassed"

                if (PACEPassed || BACPassed) {
                    statusMessage.value = "Loading DG1"
                    val dG1File = getDG1File(passportService)
                    statusMessage.value = "Loading DG2"
                    val dG2File = getDG2File(passportService)
                    statusMessage.value = "Loading SOD"
                    val sodFile = getSODFile(passportService)
                    statusMessage.value = "Chip auth"
                    val chipAuth = chipAuth(passportService)
                    val passiveAuth = doPassiveAuth(passportService, sodFile, dG1File, dG2File, chipAuth, assets)

                    statusMessage.value = "Loading Faces"
                    val faces = dG2File.faceInfos
                        .flatMap { it.faceImageInfos }
                        .map {
                            val size = it.imageLength
                            val dis = DataInputStream(it.imageInputStream)
                            val buffer = ByteArray(size)
                            dis.readFully(buffer)
                            decodeImage(it.mimeType, ByteArrayInputStream(buffer))
                        }

                    val mrzInfo = dG1File.mrzInfo
                    Log.d(TAG, "MRZ=$mrzInfo faces=${faces.size}")
                    statusMessage.value = "Loading Done"

                    passportItems.add(PassportRecordItem.TextItem("personalNumber", mrzInfo.personalNumber ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("primaryIdentifier", mrzInfo.primaryIdentifier ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("secondaryIdentifier", mrzInfo.secondaryIdentifier ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("dateOfBirth", mrzInfo.dateOfBirth ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("gender", mrzInfo.gender.name ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("nationality", mrzInfo.nationality ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("dateOfExpiry", mrzInfo.dateOfExpiry ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("documentNumber", mrzInfo.documentNumber ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("issuingState", mrzInfo.issuingState ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("documentCode", mrzInfo.documentCode ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("optionalData1", mrzInfo.optionalData1 ?: ""))
                    passportItems.add(PassportRecordItem.TextItem("optionalData2", mrzInfo.optionalData2 ?: ""))
                    faces.map { PassportRecordItem.ImageItem(it) }.forEach { passportItems.add(it) }

                } else {
                    statusMessage.value = "Authentication failure"
                }

            } else {
                statusMessage.value = "Please check passport number and dates (YYMMDD)"
            }

        }
    }

    fun changePasswordNumber(number: String) {
        passportNumber.value = number
    }

    fun changeExpDate(date: String) {
        expirationDate.value = date
    }

    fun changeBirthDate(date: String) {
        birthDate.value = date
    }

    private suspend fun tryPACE(passportService: PassportService, key: BACKey): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val cardAccessFile = CardAccessFile(passportService.getInputStream(PassportService.EF_CARD_ACCESS, PassportService.DEFAULT_MAX_BLOCKSIZE))
                cardAccessFile.securityInfos.filterIsInstance<PACEInfo>().map { paceInfo ->
                    passportService.doPACE(key, paceInfo.objectIdentifier, PACEInfo.toParameterSpec(paceInfo.parameterId), null)
                    true
                }.isNotEmpty()
            } catch (e: Exception) {
                Log.e(TAG, Log.getStackTraceString(e))
                false
            }
        }
    }

    private suspend fun tryBAC(passportService: PassportService, key: BACKey): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                passportService.getInputStream(PassportService.EF_COM, PassportService.DEFAULT_MAX_BLOCKSIZE).read()
                true
            } catch (e: Exception) {
                Log.e(TAG, Log.getStackTraceString(e))
                passportService.doBAC(key)
                false
            }
        }
    }

    private suspend fun getDG1File(passportService: PassportService): DG1File = withContext(Dispatchers.IO) {
        DG1File(passportService.getInputStream(PassportService.EF_DG1, PassportService.DEFAULT_MAX_BLOCKSIZE))
    }

    private suspend fun getDG2File(passportService: PassportService): DG2File = withContext(Dispatchers.IO) {
        DG2File(passportService.getInputStream(PassportService.EF_DG2, PassportService.DEFAULT_MAX_BLOCKSIZE))
    }

    private suspend fun getSODFile(passportService: PassportService): SODFile = withContext(Dispatchers.IO) {
        SODFile(passportService.getInputStream(PassportService.EF_SOD, PassportService.DEFAULT_MAX_BLOCKSIZE))
    }

    private suspend fun chipAuth(passportService: PassportService): Boolean = withContext(Dispatchers.IO) {
        try {
            DG14File(ByteArrayInputStream(IOUtils.toByteArray(passportService.getInputStream(PassportService.EF_DG14, PassportService.DEFAULT_MAX_BLOCKSIZE))))
                .securityInfos.filterIsInstance<ChipAuthenticationPublicKeyInfo>().map { securityInfo ->
                    passportService.doEACCA(securityInfo.keyId, ChipAuthenticationPublicKeyInfo.ID_CA_ECDH_AES_CBC_CMAC_256, securityInfo.objectIdentifier, securityInfo.subjectPublicKey)
                    true
                }.isNotEmpty()
        } catch (e: Exception) {
            Log.e(TAG, Log.getStackTraceString(e))
            false
        }
    }

    private suspend fun doPassiveAuth(
        passportService: PassportService,
        sodFile: SODFile,
        dg1File: DG1File,
        dg2File: DG2File,
        chipAuthSucceeded: Boolean,
        assets: AssetManager
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            val digest = MessageDigest.getInstance(sodFile.getDigestAlgorithm())
            val dataHashes: Map<Int, ByteArray> = sodFile.getDataGroupHashes()
            var dg14Hash: ByteArray? = ByteArray(0)
            if (chipAuthSucceeded) {
                dg14Hash = digest.digest(IOUtils.toByteArray(passportService.getInputStream(PassportService.EF_DG14, PassportService.DEFAULT_MAX_BLOCKSIZE)))
            }
            val dg1Hash = digest.digest(dg1File.getEncoded())
            val dg2Hash = digest.digest(dg2File.getEncoded())
            if (Arrays.equals(dg1Hash, dataHashes[1]) && Arrays.equals(dg2Hash, dataHashes[2]) && (!chipAuthSucceeded || Arrays.equals(dg14Hash, dataHashes[14]))) {
                // We retrieve the CSCA from the german master list
                val asn1InputStream = ASN1InputStream(assets.open("masterList"))

                val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
                keystore.load(null, null)
                val cf = CertificateFactory.getInstance("X.509")
                while (true) {
                    val p: ASN1Primitive = asn1InputStream.readObject() ?: break
                    val asn1 = ASN1Sequence.getInstance(p)
                    require(!(asn1 == null || asn1.size() == 0)) { "null or empty sequence passed." }
                    require(asn1.size() == 2) { "Incorrect sequence size: " + asn1.size() }
                    val certSet = ASN1Set.getInstance(asn1.getObjectAt(1))
                    for (i in 0 until certSet.size()) {
                        val certificate = Certificate.getInstance(certSet.getObjectAt(i))
                        val pemCertificate = certificate.encoded
                        val javaCertificate = cf.generateCertificate(ByteArrayInputStream(pemCertificate))
                        keystore.setCertificateEntry(i.toString(), javaCertificate)
                    }
                }
                val docSigningCertificates: List<X509Certificate> = sodFile.getDocSigningCertificates()
                for (docSigningCertificate in docSigningCertificates) {
                    docSigningCertificate.checkValidity()
                }

                // We check if the certificate is signed by a trusted CSCA
                // TODO: verify if certificate is revoked
                val cp = cf.generateCertPath(docSigningCertificates)
                val pkixParameters = PKIXParameters(keystore)
                pkixParameters.isRevocationEnabled = false
                val cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType())
                cpv.validate(cp, pkixParameters)
                var sodDigestEncryptionAlgorithm: String = sodFile.getDigestEncryptionAlgorithm()
                var isSSA = false
                if (sodDigestEncryptionAlgorithm == "SSAwithRSA/PSS") {
                    sodDigestEncryptionAlgorithm = "SHA256withRSA/PSS"
                    isSSA = true
                }
                val sign = Signature.getInstance(sodDigestEncryptionAlgorithm)
                if (isSSA) {
                    sign.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
                }
                sign.initVerify(sodFile.docSigningCertificate)
                sign.update(sodFile.eContent)
                sign.verify(sodFile.encryptedDigest)
                true
            } else {
                false
            }
        } catch (e: Exception) {
            Log.d(TAG, Log.getStackTraceString(e))
            false
        }
    }


    private fun isValid(passportNumber: String, expirationDate: String, birthDate: String): Boolean {
        return isPassportNumberValid(passportNumber) && isDateValid(expirationDate) && isDateValid(birthDate)
    }

    private fun isPassportNumberValid(passportNumber: String) = passportNumber.isNotEmpty()
    private fun isDateValid(date: String) = date.length == 6 && date.none { !it.isDigit() }

    fun decodeImage(mimeType: String, inputStream: InputStream?): Bitmap? {
        return if (mimeType.equals("image/jp2", ignoreCase = true) || mimeType.equals("image/jpeg2000", ignoreCase = true)) {
            JP2Decoder(inputStream).decode()
        } else if (mimeType.equals("image/x-wsq", ignoreCase = true)) {
            val wsqDecoder = WsqDecoder()
            val bitmap = wsqDecoder.decode(IOUtils.toByteArray(inputStream))
            val byteData: ByteArray = bitmap.pixels
            val intData = IntArray(byteData.size)
            for (j in byteData.indices) {

                intData[j] = (0xFF000000 or
                        (byteData[j].toInt() and 0xFF shl 16).toLong()
                        or (byteData[j].toInt() and 0xFF shl 8).toLong()
                        or (byteData[j].toInt() and 0xFF).toLong()).toInt()
            }
            Bitmap.createBitmap(intData, 0, bitmap.width, bitmap.width, bitmap.height, Bitmap.Config.ARGB_8888)
        } else {
            BitmapFactory.decodeStream(inputStream)
        }
    }

    sealed class PassportRecordItem {
        data class TextItem(val label: String, val value: String) : PassportRecordItem()
        data class ImageItem(val image: Bitmap?) : PassportRecordItem()
    }

    companion object {
        private const val TAG = "MainViewModel"
    }
}
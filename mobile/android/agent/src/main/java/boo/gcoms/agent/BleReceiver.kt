package boo.gcoms.agent

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import java.security.MessageDigest
import java.util.UUID

/**
 * Pico DS-MIN file-service receiver (protocol 4).
 *
 * The Pico advertises the shared native-delivery service 3E8AAFA0-…-0001 with a
 * control characteristic (…-0002, write), a data characteristic (…-0003,
 * notify) and a metadata characteristic (…-0005, read). This class implements
 * the host role, the same one as pico/tools/ble_delivery/{linux_receiver.py,
 * mac_receiver.jxa}: GET -> receive header+object -> VERIFIED -> EXEC -> DONE.
 *
 * The 76-byte header is "PICONAT4" + attempt(32) + size(4, big-endian) +
 * sha256(32). Objects are sha256-verified before anything is handed on; a
 * mismatch fails closed. Nothing is executed here: the verified artifact is
 * delivered to [onArtifact] and the embedding app runs it in-process.
 */
class BleReceiver(
    private val context: Context,
    private val attemptId: String,
    private val onArtifact: (role: String, bytes: ByteArray) -> Int,
    private val onFinished: (ok: Boolean, detail: String) -> Unit,
) {
    companion object {
        val SERVICE: UUID = UUID.fromString("3e8aafa0-4e1f-4f4a-bd62-3cf8bb770001")
        val CONTROL: UUID = UUID.fromString("3e8aafa0-4e1f-4f4a-bd62-3cf8bb770002")
        val DATA: UUID = UUID.fromString("3e8aafa0-4e1f-4f4a-bd62-3cf8bb770003")
        val METADATA: UUID = UUID.fromString("3e8aafa0-4e1f-4f4a-bd62-3cf8bb770005")
        val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        private const val HEADER = 76
        private val MAGIC = "PICONAT4".toByteArray(Charsets.US_ASCII)
        private val ATTEMPT_RE = Regex("[0-9a-f]{32}")
    }

    private var gatt: BluetoothGatt? = null
    private var control: BluetoothGattCharacteristic? = null
    private var data: BluetoothGattCharacteristic? = null

    private var wantRole: String? = null
    private var header = ByteArray(0)
    private var body: java.io.ByteArrayOutputStream? = null
    private var expectedSize = 0
    private var expectedHash = ByteArray(0)

    init {
        require(ATTEMPT_RE.matches(attemptId)) { "attempt id must be 32 lowercase hex chars" }
    }

    @SuppressLint("MissingPermission")
    fun start() {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val adapter: BluetoothAdapter? = manager.adapter
        if (adapter == null) { fail("no bluetooth adapter"); return }
        val scanner = adapter.bluetoothLeScanner
        if (scanner == null) { fail("no BLE scanner"); return }
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanner.startScan(listOf(filter), settings, object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                scanner.stopScan(this)
                connect(result.device)
            }
            override fun onScanFailed(errorCode: Int) { fail("scan failed $errorCode") }
        })
    }

    @SuppressLint("MissingPermission")
    private fun connect(device: BluetoothDevice) {
        gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
    }

    private val callback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                g.requestMtu(517)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED && wantRole != null) {
                fail("disconnected mid-transfer")
            }
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) { g.discoverServices() }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            val service: BluetoothGattService = g.getService(SERVICE)
            if (service == null) { fail("service missing"); return }
            control = service.getCharacteristic(CONTROL)
            data = service.getCharacteristic(DATA)
            if (control == null || data == null) { fail("characteristics missing"); return }
            g.setCharacteristicNotification(data, true)
            val cccd = data!!.getDescriptor(CCCD)
            if (cccd == null) { fail("no CCCD"); return }
            if (Build.VERSION.SDK_INT >= 33) {
                g.writeDescriptor(cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            } else {
                @Suppress("DEPRECATION") cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                @Suppress("DEPRECATION") g.writeDescriptor(cccd)
            }
        }

        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) {
            if (d.uuid == CCCD && status == BluetoothGatt.GATT_SUCCESS) get("RECEIVER")
            else if (status != BluetoothGatt.GATT_SUCCESS) fail("descriptor write $status")
        }

        override fun onCharacteristicChanged(
            g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray,
        ) {
            if (c.uuid == DATA) feed(value)
        }

        @Deprecated("API < 33")
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION") if (c.uuid == DATA) feed(c.value ?: ByteArray(0))
        }
    }

    @SuppressLint("MissingPermission")
    private fun writeControl(command: String) {
        val g = gatt
        val ch = control
        if (g == null || ch == null) { fail("not connected"); return }
        val bytes = command.toByteArray(Charsets.US_ASCII)
        if (Build.VERSION.SDK_INT >= 33) {
            g.writeCharacteristic(ch, bytes, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
        } else {
            @Suppress("DEPRECATION") ch.value = bytes
            @Suppress("DEPRECATION") g.writeCharacteristic(ch)
        }
    }

    private fun get(role: String) {
        wantRole = role
        header = ByteArray(0)
        body = null
        expectedSize = 0
        writeControl("GET $attemptId $role\n")
    }

    private fun feed(chunk: ByteArray) {
        var offset = 0
        if (header.size < HEADER) {
            val take = minOf(HEADER - header.size, chunk.size)
            header += chunk.copyOfRange(0, take)
            offset = take
            if (header.size == HEADER && !parseHeader()) return
        }
        if (header.size == HEADER && offset < chunk.size) {
            val out = body ?: java.io.ByteArrayOutputStream(expectedSize).also { body = it }
            out.write(chunk, offset, chunk.size - offset)
            if (out.size() >= expectedSize) completeObject()
        }
    }

    private fun parseHeader(): Boolean {
        for (i in MAGIC.indices) if (header[i] != MAGIC[i]) return failB("bad magic")
        val attempt = String(header, 8, 32, Charsets.US_ASCII)
        if (attempt != attemptId) return failB("attempt mismatch")
        var size = 0L
        for (i in 40 until 44) size = (size shl 8) or (header[i].toLong() and 0xff)
        if (size < 0 || size > 64L * 1024 * 1024) return failB("bad size")
        expectedSize = size.toInt()
        expectedHash = header.copyOfRange(44, 76)
        body = java.io.ByteArrayOutputStream(expectedSize)
        if (expectedSize == 0) completeObject()
        return true
    }

    private fun completeObject() {
        val role = wantRole
        if (role == null) { fail("no role"); return }
        val bytes = body?.toByteArray() ?: ByteArray(0)
        if (bytes.size != expectedSize) { fail("short object"); return }
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        if (!digest.contentEquals(expectedHash)) { fail("sha256 mismatch for $role"); return }
        wantRole = null
        when (role) {
            "RECEIVER" -> {
                writeControl("VERIFIED $attemptId RECEIVER\n")
                get("ARTIFACT")
            }
            "ARTIFACT" -> {
                writeControl("VERIFIED $attemptId ARTIFACT\n")
                val status = onArtifact("ARTIFACT", bytes)
                val pin = expectedHash.joinToString("") { "%02x".format(it) }
                writeControl("EXEC $attemptId $pin $status\n")
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun finish(ok: Boolean, detail: String) {
        gatt?.close()
        gatt = null
        onFinished(ok, detail)
    }

    private fun fail(detail: String) { finish(false, detail) }
    private fun failB(detail: String): Boolean { finish(false, detail); return false }
}

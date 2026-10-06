package com.manojarc20.tvadshield.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnStateMachineTest {
    @Test
    fun startsStopped() {
        assertEquals(VpnState.STOPPED, VpnStateMachine().state)
    }

    @Test
    fun supportsStartRunStopLifecycle() {
        val machine = VpnStateMachine()
        machine.transitionTo(VpnState.STARTING)
        machine.transitionTo(VpnState.RUNNING)
        machine.transitionTo(VpnState.STOPPING)
        machine.transitionTo(VpnState.STOPPED)
        assertEquals(VpnState.STOPPED, machine.state)
    }

    @Test
    fun incompleteStartCanEnterErrorAndStop() {
        val machine = VpnStateMachine()
        machine.transitionTo(VpnState.STARTING)
        machine.transitionTo(VpnState.ERROR)
        machine.transitionTo(VpnState.STOPPING)
        machine.transitionTo(VpnState.STOPPED)
        assertEquals(VpnState.STOPPED, machine.state)
    }

    @Test
    fun rejectsStartingDirectlyIntoRunning() {
        val machine = VpnStateMachine()
        val error = runCatching { machine.transitionTo(VpnState.RUNNING) }.exceptionOrNull()
        assertEquals(IllegalStateException::class.java, error?.javaClass)
        assertEquals(VpnState.STOPPED, machine.state)
    }

    @Test
    fun rejectsStoppingWhileAlreadyStopped() {
        val machine = VpnStateMachine()
        val error = runCatching { machine.transitionTo(VpnState.STOPPING) }.exceptionOrNull()
        assertEquals(IllegalStateException::class.java, error?.javaClass)
    }
}

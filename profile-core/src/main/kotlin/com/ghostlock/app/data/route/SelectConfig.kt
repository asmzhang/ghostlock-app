package com.ghostlock.app.data.route

/**
 * `route.select_stack` section. Mirrors native `SelectStackLayout` plus the
 * select route's `compact_waiter` key (native also reads it from `kernel`).
 * Every field is optional: absence means "not provided".
 *
 * `w3_leaf_to_target8` pins the direction the W3 leaf-directory probe lands on
 * (0 = [target], 1 = [target+8]). When a release sets it, native skips the
 * probe route and aims both seccomp writes directly; absence keeps the
 * per-run probe.
 */
data class SelectConfig(
    val waiterShift: Int?,
    val compactWaiter: UByte?,
    val w3LeafToTarget8: UByte?,
    val enterDelayUs: UInt?,
    val timeoutUs: UInt?,
) : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = buildList {
        waiterShift?.let { add("waiter_shift" to it.toLong().toULong()) }
        compactWaiter?.let { add("compact_waiter" to it.toULong()) }
        w3LeafToTarget8?.let { add("w3_leaf_to_target8" to it.toULong()) }
        enterDelayUs?.let { add("enter_delay_us" to it.toULong()) }
        timeoutUs?.let { add("timeout_us" to it.toULong()) }
    }

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "waiter_shift" -> copy(waiterShift = value.toLong().toInt())
        "compact_waiter" -> copy(compactWaiter = value.toUByte())
        "w3_leaf_to_target8" -> copy(w3LeafToTarget8 = value.toUByte())
        "enter_delay_us" -> copy(enterDelayUs = value.toUInt())
        "timeout_us" -> copy(timeoutUs = value.toUInt())
        else -> this
    }

    companion object {
        val EMPTY = SelectConfig(null, null, null, null, null)

        fun from(value: (String) -> Long?): SelectConfig = SelectConfig(
            waiterShift = value("pselect_waiter_shift")?.toInt(),
            compactWaiter = value("compact_waiter")?.toUByte(),
            w3LeafToTarget8 = value("route.select_stack.w3_leaf_to_target8")?.toUByte(),
            enterDelayUs = value("execution.routes.select_stack.enter_delay_us")?.toUInt(),
            timeoutUs = value("execution.routes.select_stack.timeout_us")?.toUInt(),
        )
    }
}

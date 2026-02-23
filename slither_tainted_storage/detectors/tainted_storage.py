"""Detect storage slots tainted by gas-dependent, CREATE2, or
sender-balance values.

Taint sources:
  - gasleft()
  - tx.gasprice, block.basefee, block.blobbasefee, block.gaslimit
  - CREATE2 result (NewContract with salt)
  - address.balance where address == msg.sender

Taint propagation:
  - Data flow: assignments, arithmetic, bitwise, hashing,
    ABI encoding, type conversions, function args/returns,
    mapping index keys, tuple unpacking
  - Control flow: if a tainted value is in a branch condition,
    all state writes inside that branch body are tainted

Taint sink: any state variable write.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.core.cfg.node import NodeType
from slither.core.declarations.solidity_variables import (
    SolidityFunction,
    SolidityVariable,
    SolidityVariableComposed,
)
from slither.core.variables.state_variable import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
)
from slither.slithir.operations import (
    Assignment,
    Binary,
    Condition,
    Index,
    InternalCall,
    NewContract,
    SolidityCall,
    TypeConversion,
    Unary,
    Unpack,
)
from slither.slithir.operations.lvalue import OperationWithLValue
from slither.slithir.variables import (
    Constant,
    ReferenceVariable,
)

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract, Function
    from slither.detectors.abstract_detector import DETECTOR_INFO


# ── helpers ──────────────────────────────────────────────────────

_GASLEFT = SolidityFunction("gasleft()")
_BALANCE = SolidityFunction("balance(address)")
_MSG_SENDER = SolidityVariableComposed("msg.sender")

# Gas-related composed variables treated as taint sources
_GAS_COMPOSED_SOURCES: dict[SolidityVariableComposed, str] = {
    SolidityVariableComposed("tx.gasprice"): "tx.gasprice",
    SolidityVariableComposed("block.basefee"): "block.basefee",
    SolidityVariableComposed("block.blobbasefee"): "block.blobbasefee",
    SolidityVariableComposed("block.gaslimit"): "block.gaslimit",
}

_HASH_AND_ENCODE = {
    SolidityFunction("keccak256()"),
    SolidityFunction("keccak256(bytes)"),
    SolidityFunction("sha3()"),
    SolidityFunction("sha256()"),
    SolidityFunction("sha256(bytes)"),
    SolidityFunction("ripemd160()"),
    SolidityFunction("ripemd160(bytes)"),
    SolidityFunction("abi.encode()"),
    SolidityFunction("abi.encodePacked()"),
    SolidityFunction("abi.encodeWithSelector()"),
    SolidityFunction("abi.encodeWithSignature()"),
    SolidityFunction("abi.encodeCall()"),
}


def _var_key(var: object) -> int | str:
    """Stable identity for a variable across IR ops."""
    if isinstance(var, StateVariable):
        return f"state:{var.canonical_name}"
    if isinstance(var, (SolidityVariableComposed, SolidityVariable)):
        return f"solidity:{var.name}"
    return id(var)


def _resolve_ref(var: object) -> object:
    """Follow ReferenceVariable chain to the origin."""
    seen: set[int] = set()
    while isinstance(var, ReferenceVariable):
        if id(var) in seen:
            break
        seen.add(id(var))
        var = var.points_to_origin
    return var


# ── per-function taint analysis ─────────────────────────────────


class _FunctionTaintCtx:
    """Taint context for a single function analysis pass."""

    def __init__(self, function: Function) -> None:
        self.function = function
        self.tainted: set[int | str] = set()
        # Variables known to alias msg.sender (by id)
        self.msg_sender_aliases: set[int] = set()
        self.tainted_state_writes: list[
            tuple[StateVariable, Node, str]
        ] = []
        self._seen_writes: set[tuple[str, int]] = set()

    def is_tainted(self, var: object) -> bool:
        return _var_key(var) in self.tainted

    def mark(self, var: object) -> None:
        self.tainted.add(_var_key(var))

    def mark_if_any_tainted(
        self, lvalue: object, reads: list[object]
    ) -> None:
        if any(
            self.is_tainted(r) for r in reads if r is not None
        ):
            if lvalue is not None:
                self.mark(lvalue)

    def is_msg_sender(self, var: object) -> bool:
        """Check if var is msg.sender or a local alias."""
        if isinstance(var, SolidityVariableComposed):
            return var == _MSG_SENDER
        return id(var) in self.msg_sender_aliases

    def mark_msg_sender_alias(self, var: object) -> None:
        self.msg_sender_aliases.add(id(var))


def _analyze_function(
    func: Function,
    call_taint_cache: dict[str, bool],
    callee_state_cache: dict[str, set[StateVariable]],
) -> list[tuple[StateVariable, Node, str]]:
    """Run taint analysis on *func* and return tainted state writes.

    Returns list of (state_var, node, reason_string).
    """
    ctx = _FunctionTaintCtx(func)

    # Phase 1: forward data-flow taint on each node in order
    for node in func.nodes:
        _process_node_data_flow(
            node, ctx, call_taint_cache, callee_state_cache
        )

    # Phase 2: control-flow taint (branches with tainted conditions)
    _propagate_control_flow_taint(func, ctx)

    # Phase 3: remove findings overwritten by a later clean write
    _remove_overwritten_findings(func, ctx)

    return ctx.tainted_state_writes


def _process_node_data_flow(
    node: Node,
    ctx: _FunctionTaintCtx,
    call_taint_cache: dict[str, bool],
    callee_state_cache: dict[str, set[StateVariable]],
) -> None:
    """Propagate data-flow taint within a single CFG node."""
    for ir in node.irs:
        # ── track msg.sender aliases ──
        if isinstance(ir, Assignment):
            if isinstance(
                ir.rvalue, SolidityVariableComposed
            ) and ir.rvalue == _MSG_SENDER:
                ctx.mark_msg_sender_alias(ir.lvalue)
            elif id(ir.rvalue) in ctx.msg_sender_aliases:
                ctx.mark_msg_sender_alias(ir.lvalue)

        # ── gas-related composed variable sources ──
        # Mark the composed variable itself so downstream
        # propagation (assignments, binary ops, etc.) sees it.
        for r in ir.read:
            if isinstance(r, SolidityVariableComposed) and r in _GAS_COMPOSED_SOURCES:
                ctx.mark(r)

        # ── taint sources ──
        if isinstance(ir, SolidityCall):
            if ir.function == _GASLEFT and ir.lvalue is not None:
                ctx.mark(ir.lvalue)
                continue
            if ir.function == _BALANCE and ir.lvalue is not None:
                args = ir.arguments
                if args and ctx.is_msg_sender(args[0]):
                    ctx.mark(ir.lvalue)
                    continue
            # Hash / abi-encode: propagate taint from args
            if ir.function in _HASH_AND_ENCODE:
                if ir.lvalue is not None:
                    ctx.mark_if_any_tainted(
                        ir.lvalue, ir.arguments
                    )
                continue

        if isinstance(ir, NewContract):
            if ir.call_salt is not None and ir.lvalue is not None:
                ctx.mark(ir.lvalue)
                continue

        # ── taint propagation ──
        if isinstance(ir, Assignment):
            if ctx.is_tainted(ir.rvalue):
                ctx.mark(ir.lvalue)
                _maybe_record_state_write(ir.lvalue, node, ctx)
            continue

        if isinstance(ir, Binary):
            ctx.mark_if_any_tainted(
                ir.lvalue, [ir.variable_left, ir.variable_right]
            )
            continue

        if isinstance(ir, Unary):
            if hasattr(ir, "rvalue") and ctx.is_tainted(
                ir.rvalue
            ):
                if ir.lvalue is not None:
                    ctx.mark(ir.lvalue)
            continue

        if isinstance(ir, TypeConversion):
            if ctx.is_tainted(ir.variable):
                if ir.lvalue is not None:
                    ctx.mark(ir.lvalue)
            if ctx.is_msg_sender(ir.variable):
                if ir.lvalue is not None:
                    ctx.mark_msg_sender_alias(ir.lvalue)
            continue

        if isinstance(ir, Index):
            tainted_key = ctx.is_tainted(ir.variable_right)
            tainted_arr = ctx.is_tainted(ir.variable_left)
            if tainted_key or tainted_arr:
                if ir.lvalue is not None:
                    ctx.mark(ir.lvalue)
            continue

        if isinstance(ir, Unpack):
            if ctx.is_tainted(ir.tuple):
                if ir.lvalue is not None:
                    ctx.mark(ir.lvalue)
            continue

        if isinstance(ir, InternalCall):
            _handle_internal_call(
                ir, node, ctx, call_taint_cache,
                callee_state_cache,
            )
            continue

        # Generic: any operation with lvalue that reads tainted
        if isinstance(ir, OperationWithLValue) and ir.lvalue:
            reads = [
                v for v in ir.read if not isinstance(v, Constant)
            ]
            ctx.mark_if_any_tainted(ir.lvalue, reads)

    # After processing all IRs, check for state writes
    for ir in node.irs:
        if isinstance(ir, OperationWithLValue) and ir.lvalue:
            _maybe_record_state_write(ir.lvalue, node, ctx)


def _handle_internal_call(
    ir: InternalCall,
    node: Node,
    ctx: _FunctionTaintCtx,
    call_taint_cache: dict[str, bool],
    callee_state_cache: dict[str, set[StateVariable]],
) -> None:
    """Propagate taint through internal function calls.

    1. If any argument is tainted or callee has taint sources,
       the return value is tainted.
    2. State variables tainted as side effects inside the callee
       are marked tainted in the caller's context.
    """
    callee = ir.function
    if callee is None or not hasattr(callee, "nodes"):
        return

    any_arg_tainted = any(
        ctx.is_tainted(a)
        for a in ir.arguments
        if not isinstance(a, Constant)
    )

    callee_key = callee.canonical_name
    if callee_key not in call_taint_cache:
        call_taint_cache[callee_key] = (
            _callee_introduces_taint(callee)
        )

    callee_has_taint = call_taint_cache[callee_key]

    if (any_arg_tainted or callee_has_taint) and ir.lvalue:
        ctx.mark(ir.lvalue)

    # Propagate side effects: state variables tainted by callee
    tainted_state = _callee_tainted_state_vars(
        callee, call_taint_cache, callee_state_cache
    )
    for sv in tainted_state:
        ctx.mark(sv)

    # Propagate through callee when caller context has tainted
    # state vars that the callee reads and writes to other vars.
    _propagate_caller_taint_through_callee(callee, ctx)


def _propagate_caller_taint_through_callee(
    callee: Function,
    ctx: _FunctionTaintCtx,
) -> None:
    """Mark state vars written by callee from state vars tainted
    in the caller's context.

    When f() calls _taint() then _copy(), _taint() marks
    taintedVar in ctx. _copy() reads taintedVar and writes
    copiedVar. This function propagates that chain.
    """
    local_taint: set[int | str] = set()
    for node in callee.nodes:
        for ir in node.irs:
            if not (
                isinstance(ir, OperationWithLValue)
                and ir.lvalue is not None
            ):
                continue
            reads = [
                v for v in ir.read
                if not isinstance(v, Constant)
            ]
            if any(
                ctx.is_tainted(r) or _var_key(r) in local_taint
                for r in reads
            ):
                local_taint.add(_var_key(ir.lvalue))
                target = _resolve_ref(ir.lvalue)
                if isinstance(target, StateVariable):
                    ctx.mark(target)


def _callee_introduces_taint(func: Function) -> bool:
    """Return True if the function body contains taint sources."""
    for node in func.nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall):
                if ir.function == _GASLEFT:
                    return True
                if ir.function == _BALANCE:
                    args = ir.arguments
                    if args and isinstance(
                        args[0], SolidityVariableComposed
                    ):
                        if args[0] == _MSG_SENDER:
                            return True
            if isinstance(ir, NewContract):
                if ir.call_salt is not None:
                    return True
            for r in ir.read:
                if (
                    isinstance(r, SolidityVariableComposed)
                    and r in _GAS_COMPOSED_SOURCES
                ):
                    return True
    return False


def _callee_tainted_state_vars(
    func: Function,
    call_taint_cache: dict[str, bool],
    callee_state_cache: dict[str, set[StateVariable]],
) -> set[StateVariable]:
    """Analyze callee to find state variables it taints.

    Runs a lightweight taint analysis on the callee's body to
    determine which state variables are written with tainted
    values. Results are cached.
    """
    key = (
        func.canonical_name
        if hasattr(func, "canonical_name")
        else ""
    )
    if key in callee_state_cache:
        return callee_state_cache[key]

    # Prevent infinite recursion
    callee_state_cache[key] = set()

    # Run a mini taint analysis on the callee
    if func.contract_declarer is None:
        return set()

    writes = _analyze_function(
        func, call_taint_cache, callee_state_cache
    )
    result = {sv for sv, _node, _reason in writes}
    callee_state_cache[key] = result
    return result


def _maybe_record_state_write(
    lvalue: object,
    node: Node,
    ctx: _FunctionTaintCtx,
) -> None:
    """If lvalue resolves to a state variable and is tainted."""
    target = _resolve_ref(lvalue)
    if isinstance(target, StateVariable) and ctx.is_tainted(
        lvalue
    ):
        key = (target.canonical_name, id(node))
        if key not in ctx._seen_writes:
            reason = _infer_reason(ctx)
            ctx._seen_writes.add(key)
            ctx.tainted_state_writes.append(
                (target, node, reason)
            )


def _infer_reason(ctx: _FunctionTaintCtx) -> str:
    """Infer which taint source caused the write.

    Result is cached per ctx since the function body is constant.
    """
    if not hasattr(ctx, "_cached_reason"):
        reasons: set[str] = set()
        _collect_reasons(ctx.function, reasons, set())
        ordered = sorted(reasons)
        ctx._cached_reason = (
            ", ".join(ordered) if ordered else "tainted source"
        )
    return ctx._cached_reason


def _collect_reasons(
    func: Function,
    reasons: set[str],
    visited: set[str],
) -> None:
    """Recursively collect taint source names from a function."""
    key = (
        func.canonical_name
        if hasattr(func, "canonical_name")
        else str(func)
    )
    if key in visited:
        return
    visited.add(key)

    has_msg_sender_ref = False
    has_non_sender_balance = False
    callees: list[Function] = []

    for n in func.nodes:
        for ir in n.irs:
            # Track msg.sender references
            if isinstance(ir, Assignment):
                if (
                    isinstance(ir.rvalue, SolidityVariableComposed)
                    and ir.rvalue == _MSG_SENDER
                ):
                    has_msg_sender_ref = True

            # Gas-related composed variables
            for r in ir.read:
                if (
                    isinstance(r, SolidityVariableComposed)
                    and r in _GAS_COMPOSED_SOURCES
                ):
                    reasons.add(_GAS_COMPOSED_SOURCES[r])

            if isinstance(ir, SolidityCall):
                if ir.function == _GASLEFT:
                    reasons.add("gasleft()")
                if ir.function == _BALANCE:
                    args = ir.arguments
                    if args and isinstance(
                        args[0], SolidityVariableComposed
                    ) and args[0] == _MSG_SENDER:
                        reasons.add("msg.sender.balance")
                    elif args:
                        has_non_sender_balance = True

            if (
                isinstance(ir, NewContract)
                and ir.call_salt is not None
            ):
                reasons.add("CREATE2")

            if isinstance(ir, InternalCall) and ir.function:
                callee = ir.function
                if hasattr(callee, "nodes"):
                    callees.append(callee)

    # balance(x) where x is a local alias of msg.sender
    if has_non_sender_balance:
        if has_msg_sender_ref:
            reasons.add("msg.sender.balance")
        else:
            reasons.add("address.balance")

    for callee in callees:
        _collect_reasons(callee, reasons, visited)


# ── overwrite elimination ────────────────────────────────────────


def _remove_overwritten_findings(
    func: Function,
    ctx: _FunctionTaintCtx,
) -> None:
    """Remove findings for state vars unconditionally overwritten
    by a clean value later in the same function.

    Only considers writes at branch-depth 0 (unconditional). If
    the last unconditional write to a variable is clean, all
    findings for that variable are removed.
    """
    if not ctx.tainted_state_writes:
        return

    # Compute branch depth for each node.
    # Depth 0 = unconditional (main execution path).
    branch_depth: dict[int, int] = {}
    depth = 0
    for node in func.nodes:
        if node.type in (NodeType.IF, NodeType.IFLOOP):
            branch_depth[id(node)] = depth
            depth += 1
        elif node.type is NodeType.ENDIF:
            depth = max(depth - 1, 0)
            branch_depth[id(node)] = depth
        else:
            branch_depth[id(node)] = depth

    node_order = {id(n): i for i, n in enumerate(func.nodes)}

    # Collect unconditional state-variable assignments
    # (node_index, is_rvalue_tainted)
    writes: dict[str, list[tuple[int, bool]]] = {}
    for node in func.nodes:
        if branch_depth.get(id(node), 0) != 0:
            continue
        idx = node_order.get(id(node), -1)
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            if ir.lvalue is None:
                continue
            # Skip reference-based writes (mapping/array/struct)
            # because writing to map[k1] doesn't overwrite map[k2]
            if isinstance(ir.lvalue, ReferenceVariable):
                continue
            target = _resolve_ref(ir.lvalue)
            if not isinstance(target, StateVariable):
                continue
            is_tainted = ctx.is_tainted(ir.rvalue)
            cname = target.canonical_name
            if cname not in writes:
                writes[cname] = []
            writes[cname].append((idx, is_tainted))

    to_remove: set[str] = set()
    for cname, write_list in writes.items():
        if not write_list:
            continue
        write_list.sort(key=lambda x: x[0])
        _last_idx, last_tainted = write_list[-1]
        if not last_tainted:
            to_remove.add(cname)

    if to_remove:
        ctx.tainted_state_writes = [
            (sv, n, r)
            for sv, n, r in ctx.tainted_state_writes
            if sv.canonical_name not in to_remove
        ]
        ctx._seen_writes = {
            (sv.canonical_name, id(n))
            for sv, n, _ in ctx.tainted_state_writes
        }


# ── control-flow taint ──────────────────────────────────────────


def _propagate_control_flow_taint(
    func: Function,
    ctx: _FunctionTaintCtx,
) -> None:
    """If a branch condition is tainted, all state writes in that
    branch body are considered tainted."""
    for node in func.nodes:
        if node.type not in (NodeType.IF, NodeType.IFLOOP):
            continue
        cond_tainted = False
        for ir in node.irs:
            if isinstance(ir, Condition):
                if ctx.is_tainted(ir.value):
                    cond_tainted = True
            if isinstance(ir, OperationWithLValue):
                reads = [
                    v
                    for v in ir.read
                    if not isinstance(v, Constant)
                ]
                if any(ctx.is_tainted(r) for r in reads):
                    if ir.lvalue is not None:
                        ctx.mark(ir.lvalue)

        if not cond_tainted:
            continue

        branch_nodes = _collect_branch_body(node)
        for bn in branch_nodes:
            for sv in bn.state_variables_written:
                key = (sv.canonical_name, id(bn))
                if key not in ctx._seen_writes:
                    reason = _infer_reason(ctx)
                    ctx._seen_writes.add(key)
                    ctx.tainted_state_writes.append(
                        (sv, bn, reason)
                    )


def _collect_branch_body(if_node: Node) -> list[Node]:
    """Collect nodes in the body of an if-branch.

    Walk from if_node's sons until we hit the ENDIF merge node.
    """
    result: list[Node] = []
    visited: set[int] = {id(if_node)}
    worklist: list[Node] = list(if_node.sons)

    while worklist:
        current = worklist.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        if current.type is NodeType.ENDIF:
            continue
        result.append(current)
        for son in current.sons:
            if id(son) not in visited:
                worklist.append(son)
    return result


# ── storage slot lookup ──────────────────────────────────────────


def _get_storage_slot(
    contract: Contract,
    var: StateVariable,
    compilation_unit: object,
) -> tuple[int, int]:
    """Return (slot, offset_bytes) for a state variable."""
    try:
        return compilation_unit.storage_layout_of(contract, var)
    except (KeyError, AttributeError):
        return (-1, -1)


# ── detector class ──────────────────────────────────────────────


class TaintedStorage(AbstractDetector):
    ARGUMENT = "tainted-storage"
    HELP = (
        "State variables tainted by gasleft, gas-related globals, "
        "CREATE2, or sender balance"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = (
        "https://github.com/crytic/slither/wiki/tainted-storage"
    )
    WIKI_TITLE = (
        "Storage tainted by gas-dependent or CREATE2 values"
    )
    WIKI_DESCRIPTION = (
        "Detects state variables whose stored value depends on "
        "`gasleft()`, `tx.gasprice`, `block.basefee`, "
        "`block.blobbasefee`, `block.gaslimit`, the address "
        "returned by CREATE2, or `msg.sender.balance`. These "
        "values are non-deterministic or manipulable and storing "
        "them can lead to unexpected contract behavior."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Example {
    uint256 public gasSnapshot;
    function save() external {
        gasSnapshot = gasleft();
    }
}
```
`gasSnapshot` depends on remaining gas, which varies per call and
can be manipulated by callers to influence contract state."""
    WIKI_RECOMMENDATION = (
        "Avoid storing values derived from `gasleft()`, "
        "`tx.gasprice`, `block.basefee`, `block.blobbasefee`, "
        "`block.gaslimit`, CREATE2 deployment addresses, or "
        "`msg.sender.balance` in contract storage. If needed, "
        "document the non-determinism clearly and add validation "
        "logic."
    )

    def _detect(self) -> list:
        results = []
        call_taint_cache: dict[str, bool] = {}
        callee_state_cache: dict[str, set[StateVariable]] = {}
        seen: set[tuple[str, str]] = set()

        for contract in self.compilation_unit.contracts_derived:
            # Analyze both functions and modifiers
            analyzable = list(contract.functions_declared) + list(
                contract.modifiers_declared
            )
            # Include inherited modifiers not declared locally
            for mod in contract.modifiers:
                if mod not in analyzable:
                    analyzable.append(mod)
            for func in analyzable:
                if not func.is_implemented:
                    continue
                writes = _analyze_function(
                    func, call_taint_cache,
                    callee_state_cache,
                )
                for state_var, node, reason in writes:
                    key = (
                        state_var.canonical_name,
                        func.canonical_name,
                    )
                    if key in seen:
                        continue
                    seen.add(key)

                    slot, offset = _get_storage_slot(
                        contract,
                        state_var,
                        self.compilation_unit,
                    )
                    slot_hex = f"0x{slot:064x}"

                    info: DETECTOR_INFO = [
                        state_var,
                        f" (slot: {slot}, offset: {offset})"
                        f" is tainted by ",
                        reason,
                        " in ",
                        func,
                        "\n\t",
                        node,
                        "\n",
                    ]
                    extra = {
                        "tainted_storage": {
                            "variable": (
                                state_var.canonical_name
                            ),
                            "contract": contract.name,
                            "slot": slot,
                            "slot_hex": slot_hex,
                            "offset": offset,
                            "taint_source": reason,
                            "function": (
                                func.canonical_name
                            ),
                        }
                    }
                    results.append(
                        self.generate_result(
                            info, additional_fields=extra
                        )
                    )
        return results

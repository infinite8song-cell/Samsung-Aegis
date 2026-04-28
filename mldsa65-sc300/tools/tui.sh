#!/usr/bin/env bash
# impl_sc300/tools/tui.sh —
# Interactive build + QEMU-test + library-archive menu for impl_sc300.
# Host-aware: on macOS shows dev workflow (Claude iteration + QEMU);
#             on Ubuntu shows delivery workflow (armclang library + QEMU).
#
# Pure bash + basic tput — no whiptail/dialog required.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMPL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/env.sh"

# ------------------------------------------------------------------ #
# UI helpers                                                           #
# ------------------------------------------------------------------ #
_c_bold=$(tput bold 2>/dev/null || echo)
_c_dim=$(tput dim 2>/dev/null || echo)
_c_red=$(tput setaf 1 2>/dev/null || echo)
_c_grn=$(tput setaf 2 2>/dev/null || echo)
_c_ylw=$(tput setaf 3 2>/dev/null || echo)
_c_cya=$(tput setaf 6 2>/dev/null || echo)
_c_rst=$(tput sgr0 2>/dev/null || echo)

hr()    { printf '%s\n' "----------------------------------------"; }
title() { printf '%s%s%s\n' "$_c_bold" "$*" "$_c_rst"; }
ok()    { printf '%s%s%s\n' "$_c_grn"  "$*" "$_c_rst"; }
warn()  { printf '%s%s%s\n' "$_c_ylw"  "$*" "$_c_rst"; }
err()   { printf '%s%s%s\n' "$_c_red"  "$*" "$_c_rst"; }
dim()   { printf '%s%s%s\n' "$_c_dim"  "$*" "$_c_rst"; }

pause() { read -rp "[enter to continue] " _; }

OUT_DIR="$IMPL_DIR/output"
LOG_DIR="$IMPL_DIR/log"

# show_artifacts <header> <relpath> [<relpath>...]
#   Relative to OUT_DIR; lists existing files with absolute path + size.
show_artifacts() {
    local hdr="$1"; shift
    local f p sz any=0
    echo
    title "$hdr"
    hr
    for f in "$@"; do
        if [ -e "$OUT_DIR/$f" ]; then
            p="$OUT_DIR/$f"
            sz=$(wc -c <"$p" | tr -d ' ')
            printf '  %s  (%s bytes)\n' "$p" "$sz"
            any=1
        fi
    done
    [ $any -eq 0 ] && dim "  (no artifact present under $OUT_DIR)"
}

# print_hint <label> <lines...>
print_hint() {
    local label="$1"; shift
    echo
    dim "next steps ($label):"
    local line
    for line in "$@"; do
        dim "  $ $line"
    done
}

ask() {
    # ask "prompt" default
    local prompt="$1" def="${2-}"
    local ans
    if [ -n "$def" ]; then
        read -rp "$prompt [$def]: " ans
        echo "${ans:-$def}"
    else
        read -rp "$prompt: " ans
        echo "$ans"
    fi
}

yesno() {
    # yesno "prompt" default(y|n)
    local prompt="$1" def="${2:-n}" ans
    read -rp "$prompt [$def]: " ans
    ans="${ans:-$def}"
    case "$ans" in y|Y|yes) return 0;; *) return 1;; esac
}

menu() {
    # menu "header" "option1" "option2" ...
    local header="$1"; shift
    local i=1 opt choice
    echo
    title "$header"
    hr
    for opt in "$@"; do
        printf '  %d) %s\n' "$i" "$opt"
        i=$((i+1))
    done
    printf '  q) Back / quit\n'
    hr
    read -rp "Select: " choice
    echo "$choice"
}

# ------------------------------------------------------------------ #
# Masking selection sub-menu                                           #
# Returns chosen defines in global CHOSEN_MASK                         #
# ------------------------------------------------------------------ #
CHOSEN_MASK=""
choose_masking() {
    local defs=()
    local i

    echo
    title "Masking steps"
    dim "Real 1st-order masking: Step 1, 2, 3"
    dim "Cost emulation only:    Step 4, 5, 6"
    hr
    local -a labels=(
        "MLDSA_MASK_RHOPRIME   Step 1  real  Boolean-masked Keccak for rho''"
        "MLDSA_MASK_CS1        Step 2  real  Arithmetic masked Phase 2a (cs1)"
        "MLDSA_MASK_CS2_CT0    Step 3  real  Arithmetic masked Phase 2b (s2,t0)"
        "MLDSA_MASK_Y_SAMPLE   Step 4  emu   Masked SHAKE for y sampling"
        "MLDSA_MASK_CHKNORM    Step 5  emu   Constant-time chknorm + refresh"
        "MLDSA_MASK_BA         Step 6  emu   B<->A conversion cost emulation"
    )
    local -a names=(
        MLDSA_MASK_RHOPRIME MLDSA_MASK_CS1 MLDSA_MASK_CS2_CT0
        MLDSA_MASK_Y_SAMPLE MLDSA_MASK_CHKNORM MLDSA_MASK_BA
    )
    for i in "${!labels[@]}"; do
        printf '  [%d] %s\n' $((i+1)) "${labels[$i]}"
    done
    hr
    echo "Quick presets:"
    echo "  r = real masking only (Step 1+2+3)"
    echo "  a = all steps (also sets MLDSA_MASK_ACCEPT_EMULATION)"
    echo "  n = none"
    hr
    local sel
    sel=$(ask "Enter digits like '123', or r/a/n" "n")

    case "$sel" in
        r|R) defs=(-DMLDSA_MASK_RHOPRIME -DMLDSA_MASK_CS1 -DMLDSA_MASK_CS2_CT0) ;;
        a|A) defs=(-DMLDSA_MASK_RHOPRIME -DMLDSA_MASK_CS1 -DMLDSA_MASK_CS2_CT0
                   -DMLDSA_MASK_Y_SAMPLE -DMLDSA_MASK_CHKNORM -DMLDSA_MASK_BA
                   -DMLDSA_MASK_ACCEPT_EMULATION) ;;
        n|N) defs=() ;;
        *)
            local has_emu=0
            for ((i=0;i<${#sel};i++)); do
                local d="${sel:$i:1}"
                case "$d" in
                    1) defs+=(-D${names[0]}) ;;
                    2) defs+=(-D${names[1]}) ;;
                    3) defs+=(-D${names[2]}) ;;
                    4) defs+=(-D${names[3]}); has_emu=1 ;;
                    5) defs+=(-D${names[4]}); has_emu=1 ;;
                    6) defs+=(-D${names[5]}); has_emu=1 ;;
                esac
            done
            if [ $has_emu -eq 1 ]; then
                if yesno "Add MLDSA_MASK_ACCEPT_EMULATION to silence #warning?" y; then
                    defs+=(-DMLDSA_MASK_ACCEPT_EMULATION)
                fi
            fi
            ;;
    esac

    CHOSEN_MASK="${defs[*]}"
    if [ -z "$CHOSEN_MASK" ]; then
        dim "(no masking)"
    else
        ok  "selected: $CHOSEN_MASK"
    fi
}

# ------------------------------------------------------------------ #
# Actions                                                              #
# ------------------------------------------------------------------ #
action_qemu_test() {
    local mk=Makefile.gcc
    choose_masking
    echo
    if ! check_gnu_tc; then err "GNU_TC missing: $GNU_TC"; pause; return; fi
    if ! check_qemu;   then err "QEMU missing: $QEMU";     pause; return; fi

    title "QEMU test — baseline + three gates"
    hr
    (cd "$IMPL_DIR" && \
        make -f $mk clean >/dev/null 2>&1 && \
        make -f $mk build EXTRA_CFLAGS="$CHOSEN_MASK" GNU_TC="$GNU_TC" QEMU="$QEMU" ) \
        || { err "Build failed."; pause; return; }
    echo
    (cd "$IMPL_DIR" && make -f $mk qemu GNU_TC="$GNU_TC" QEMU="$QEMU") \
        || { err "QEMU run failed."; pause; return; }
    show_artifacts "Produced artifacts" \
        mldsa65_test.elf mldsa65_test.bin
    print_hint "re-run without rebuilding" \
        "cd $IMPL_DIR" \
        "make -f Makefile.gcc qemu GNU_TC=\"$GNU_TC\" QEMU=\"$QEMU\""
    print_hint "log the qemu output to log/" \
        "make -f Makefile.gcc qemu ... 2>&1 | tee $LOG_DIR/s8_$(date +%Y%m%d_%H%M%S).log"
    pause
}

# ------------------------------------------------------------------ #
# Full KAT verification                                                #
# ------------------------------------------------------------------ #

_run_qemu_full() {
    # _run_qemu_full <mode:44|65> <variant:baseline|allmask>
    local mode=$1 variant=${2:-baseline}
    local mk elf tc_label
    local -a make_args
    local tgt; [ "$mode" = "65" ] && tgt="build" || tgt="build${mode}"

    if [ "$HOST_ROLE" = delivery ]; then
        mk=Makefile.armclang
        elf="$OUT_DIR/mldsa${mode}_test_armclang.elf"
        make_args=(ARMCLANG="$ARMCLANG" ARMAR="$ARMAR" QEMU="$QEMU")
        tc_label="armclang"
        if ! check_armclang; then err "ARMCLANG missing: $ARMCLANG"; pause; return 1; fi
    else
        mk=Makefile.gcc
        elf="$OUT_DIR/mldsa${mode}_test.elf"
        make_args=(GNU_TC="$GNU_TC" QEMU="$QEMU")
        tc_label="gcc"
        if ! check_gnu_tc; then err "GNU_TC missing: $GNU_TC"; pause; return 1; fi
    fi

    local variant_label extra_cflags
    if [ "$variant" = "allmask" ]; then
        variant_label="all-masking (steps 1-6)"
        extra_cflags="-DMLDSA_MASK_RHOPRIME -DMLDSA_MASK_CS1 -DMLDSA_MASK_CS2_CT0 -DMLDSA_MASK_Y_SAMPLE -DMLDSA_MASK_CHKNORM -DMLDSA_MASK_BA -DMLDSA_MASK_ACCEPT_EMULATION"
    else
        variant_label="baseline (no masking)"
        extra_cflags=""
    fi

    title "ML-DSA-${mode}: full ACVP KAT (115 NIST vectors) — $tc_label / $variant_label"
    hr
    if ! check_qemu; then err "QEMU missing: $QEMU"; pause; return 1; fi

    ok "Building full KAT ELF ($tc_label, $variant_label)..."
    (cd "$IMPL_DIR" && make -B -f $mk "$tgt" EXTRA_CFLAGS="$extra_cflags" "${make_args[@]}") \
        || { err "Build failed."; return 1; }

    echo
    ok "Running QEMU (full KAT)..."
    mkdir -p "$OUT_DIR/log"
    local log="$OUT_DIR/log/mldsa${mode}_kat_${variant}_$(date +%Y%m%d_%H%M%S).log"
    "$QEMU" -M mps2-an385 -nographic -semihosting -kernel "$elf" 2>&1 | tee "$log"

    echo
    if grep -q 'FAIL' "$log"; then
        err "ML-DSA-${mode} full KAT ($variant_label): FAIL — check $log"
        return 1
    fi
    if grep -q 'KAT-GATE: PASS' "$log"; then
        ok "ML-DSA-${mode} full KAT ($variant_label): PASS"
    else
        err "ML-DSA-${mode} full KAT ($variant_label): unexpected output — check $log"
        return 1
    fi
}

_run_qemu_full_both_variants() {
    # <mode:44|65> — run baseline then all-masking
    local mode=$1
    _run_qemu_full "$mode" baseline || return 1
    echo
    _run_qemu_full "$mode" allmask  || return 1
}

action_qemu_full() {
    local mode
    mode=$(ask "Param set (44|65|both)" "both")
    echo
    case "$mode" in
        44)   _run_qemu_full_both_variants 44 ;;
        65)   _run_qemu_full_both_variants 65 ;;
        both) _run_qemu_full_both_variants 65 && _run_qemu_full_both_variants 44 ;;
        *)    err "Unknown param set '$mode'"; pause; return ;;
    esac
    pause
}

# ------------------------------------------------------------------ #
# ML-KEM-768 QEMU verify (deterministic ACVP-style KAT, 3 vectors)     #
# ------------------------------------------------------------------ #
action_qemu_kem768() {
    local mk elf tc_label
    local -a make_args
    if [ "$HOST_ROLE" = delivery ]; then
        mk=Makefile.armclang
        elf="$OUT_DIR/mlkem768_test_armclang.elf"
        make_args=(ARMCLANG="$ARMCLANG" ARMAR="$ARMAR" QEMU="$QEMU")
        tc_label="armclang"
        if ! check_armclang; then err "ARMCLANG missing: $ARMCLANG"; pause; return; fi
    else
        mk=Makefile.gcc
        elf="$OUT_DIR/mlkem768_test.elf"
        make_args=(GNU_TC="$GNU_TC" QEMU="$QEMU")
        tc_label="gcc"
        if ! check_gnu_tc; then err "GNU_TC missing: $GNU_TC"; pause; return; fi
    fi

    title "ML-KEM-768: KAT ($tc_label)"
    hr
    if ! check_qemu; then err "QEMU missing: $QEMU"; pause; return; fi

    ok "Building ML-KEM-768 ELF ($tc_label)..."
    (cd "$IMPL_DIR" && make -B -f $mk build_kem768 "${make_args[@]}" -s) \
        || { err "Build failed."; pause; return; }

    echo
    ok "Running QEMU (ML-KEM-768)..."
    mkdir -p "$OUT_DIR/log"
    local log="$OUT_DIR/log/mlkem768_${tc_label}_$(date +%Y%m%d_%H%M%S).log"
    "$QEMU" -M mps2-an385 -nographic -semihosting -kernel "$elf" 2>&1 | tee "$log"

    echo
    if grep -q 'FAIL' "$log"; then
        err "ML-KEM-768 KAT: FAIL — check $log"
    elif grep -q 'KAT-GATE: PASS' "$log"; then
        ok "ML-KEM-768 KAT: PASS"
    else
        err "ML-KEM-768 KAT: unexpected output — check $log"
    fi
    pause
}

action_perf_report() {
    local mk elf65 elf44 tc_label
    local -a make_args
    if [ "$HOST_ROLE" = delivery ]; then
        mk=Makefile.armclang
        elf65="$OUT_DIR/mldsa65_test_armclang.elf"
        elf44="$OUT_DIR/mldsa44_test_armclang.elf"
        make_args=(ARMCLANG="$ARMCLANG" ARMAR="$ARMAR")
        tc_label="armclang"
        if ! check_armclang; then err "ARMCLANG missing: $ARMCLANG"; pause; return; fi
    else
        mk=Makefile.gcc
        elf65="$OUT_DIR/mldsa65_test.elf"
        elf44="$OUT_DIR/mldsa44_test.elf"
        make_args=(GNU_TC="$GNU_TC")
        tc_label="gcc"
        if ! check_gnu_tc; then err "GNU_TC missing: $GNU_TC"; pause; return; fi
    fi

    title "Cycle & Stack Report — $tc_label / QEMU mps2-an385 (Cortex-M3)"
    hr
    if ! check_qemu; then err "QEMU missing: $QEMU"; pause; return; fi

    mkdir -p "$OUT_DIR/log"
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local log44="$OUT_DIR/log/perf44_${tc_label}_${ts}.log"
    local log65="$OUT_DIR/log/perf65_${tc_label}_${ts}.log"

    # ── Baseline (no masking) ─────────────────────────────────────────────
    ok "Building baseline ELFs (no masking, $tc_label)..."
    (cd "$IMPL_DIR" && \
        make -f $mk build build44 "${make_args[@]}" -s) \
        || { err "Build failed."; pause; return; }

    ok "QEMU ML-DSA-65 (baseline)..."
    "$QEMU" -M mps2-an385 -nographic -semihosting \
        -kernel "$elf65" >"$log65" 2>&1
    ok "QEMU ML-DSA-44 (baseline)..."
    "$QEMU" -M mps2-an385 -nographic -semihosting \
        -kernel "$elf44" >"$log44" 2>&1

    echo
    awk -v f44="$log44" -v f65="$log65" '
    function comma(n,    s, r) {
        n = int(n); r = ""
        if (n == 0) return "-"
        s = sprintf("%d", n)
        while (length(s) > 3) {
            r = "," substr(s, length(s)-2) r
            s = substr(s, 1, length(s)-3)
        }
        return s r
    }
    function estms(cyc,    v, s, r) {
        if (cyc == 0) return "-"
        v = int(cyc * 75 / 70000 + 0.5)
        s = sprintf("%d", v); r = ""
        while (length(s) > 3) {
            r = "," substr(s, length(s)-2) r
            s = substr(s, 1, length(s)-3)
        }
        return s r " ms"
    }
    function load(fname, pfx,    line, a, op, metric, val) {
        while ((getline line < fname) > 0) {
            if (line ~ /,gcc,[^,]+,(cycles|stack):/) {
                split(line, a, ",")
                op = a[3]; metric = a[4]; sub(/:$/, "", metric)
                getline val < fname
                d[pfx, op, metric] = val + 0
            }
            if (line ~ /^KAT,avg,[^,]+,cycles:/) {
                split(line, a, ",")
                op = a[3]
                getline val < fname
                d[pfx, op, "kat_cycles"] = val + 0
            }
        }
        close(fname)
    }
    function getcyc(pfx, kop, sop) {
        if ((pfx, kop, "kat_cycles") in d) return d[pfx, kop, "kat_cycles"]
        return d[pfx, sop, "cycles"]
    }
    BEGIN {
        load(f44, "44"); load(f65, "65")
        SEP = "  ─────────────────────────────────────────────────────────────────────────"
        lbl[1]="keypair (25)";   sop[1]="keypair";         kop[1]="keypair"
        lbl[2]="sign_int (30)";  sop[2]="sign_internal";   kop[2]="sign_internal"
        lbl[3]="sign_ext (30)";  sop[3]="sign";            kop[3]="sign_external"
        lbl[4]="vrfy_int (15)";  sop[4]="verify_internal"; kop[4]="verify_internal"
        lbl[5]="vrfy_ext (15)";  sop[5]="verify";          kop[5]="verify_external"
        printf "  %-16s %-7s %12s %12s %12s %12s\n",
            "Operation", "Metric", "ML-DSA-44", "ML-DSA-65", "est ms(44)", "est ms(65)"
        print SEP
        for (i = 1; i <= 5; i++) {
            cyc44 = getcyc("44", kop[i], sop[i])
            cyc65 = getcyc("65", kop[i], sop[i])
            printf "  %-16s %-7s %12s %12s %12s %12s\n",
                lbl[i], "cycles",
                comma(cyc44), comma(cyc65), estms(cyc44), estms(cyc65)
            printf "  %-16s %-7s %12s %12s\n", "", "stack B",
                comma(d["44", sop[i], "stack"]),
                comma(d["65", sop[i], "stack"])
        }
        print SEP
        printf "\n"
    }
    ' /dev/null

    # ── Per-masking-step overhead ─────────────────────────────────────────
    title "SCA masking overhead — building 6 variants..."
    hr

    local tmpdir; tmpdir=$(mktemp -d)
    local -a mflags=(
        "-DMLDSA_MASK_RHOPRIME"
        "-DMLDSA_MASK_CS1"
        "-DMLDSA_MASK_CS2_CT0"
        "-DMLDSA_MASK_Y_SAMPLE -DMLDSA_MASK_ACCEPT_EMULATION"
        "-DMLDSA_MASK_CHKNORM -DMLDSA_MASK_ACCEPT_EMULATION"
        "-DMLDSA_MASK_BA -DMLDSA_MASK_ACCEPT_EMULATION"
    )
    local -a mlabels=(
        "Step1 RHOPRIME  (real)"
        "Step2 CS1       (real)"
        "Step3 CS2_CT0   (real)"
        "Step4 Y_SAMPLE  (emu)"
        "Step5 CHKNORM   (emu)"
        "Step6 BA        (emu)"
    )

    local step
    for step in 0 1 2 3 4 5; do
        dim "  [${step}/5] ${mlabels[$step]}..."
        if (cd "$IMPL_DIR" && \
                make -B -f $mk build build44 \
                    EXTRA_CFLAGS="${mflags[$step]}" "${make_args[@]}" -s \
                    >/dev/null 2>&1); then
            "$QEMU" -M mps2-an385 -nographic -semihosting \
                -kernel "$elf65" \
                >"$tmpdir/m${step}_65.log" 2>&1
            "$QEMU" -M mps2-an385 -nographic -semihosting \
                -kernel "$elf44" \
                >"$tmpdir/m${step}_44.log" 2>&1
        else
            warn "  Build failed for ${mlabels[$step]} — skipped."
            touch "$tmpdir/m${step}_65.log" "$tmpdir/m${step}_44.log"
        fi
    done

    dim "Restoring baseline ELFs..."
    (cd "$IMPL_DIR" && make -B -f $mk build build44 "${make_args[@]}" -s >/dev/null 2>&1)

    echo
    awk -v log44b="$log44" -v log65b="$log65" -v tmpdir="$tmpdir" '
    function loadcyc(fname, pfx,    line, a, op, metric, val) {
        while ((getline line < fname) > 0) {
            if (line ~ /,gcc,[^,]+,(cycles|stack):/) {
                split(line, a, ","); op = a[3]; metric = a[4]; sub(/:$/, "", metric)
                getline val < fname; d[pfx, op, metric] = val + 0
            }
            if (line ~ /^KAT,avg,[^,]+,cycles:/) {
                split(line, a, ","); op = a[3]
                getline val < fname; d[pfx, op, "kat"] = val + 0
            }
        }
        close(fname)
    }
    function cyc(pfx, op) {
        if ((pfx, op, "kat") in d) return d[pfx, op, "kat"]
        return d[pfx, op, "cycles"]
    }
    function estms_val(c) { return (c == 0) ? 0 : int(c * 75 / 70000 + 0.5) }
    function estms_str(c,    v, s, r) {
        if (c == 0) return "-"
        v = estms_val(c); s = sprintf("%d", v); r = ""
        while (length(s) > 3) { r = "," substr(s, length(s)-2) r; s = substr(s, 1, length(s)-3) }
        return s r " ms"
    }
    function comma_str(n,    s, r) {
        n = int(n); if (n == 0) return "-"
        s = sprintf("%d", n); r = ""
        while (length(s) > 3) { r = "," substr(s, length(s)-2) r; s = substr(s, 1, length(s)-3) }
        return s r
    }
    function fmt_cell(str, val, ref,    W, pr, pct, col, RST, ptag, full, i) {
        W = 14; RST = "\033[0m"
        if (ref == 0 || val == 0 || val == ref) {
            full = str; for (i = length(full); i < W; i++) full = " " full; return full
        }
        pr = (val - ref) * 100.0 / ref
        pct = int(pr >= 0 ? pr + 0.5 : pr - 0.5)
        if (pct == 0) {
            full = str; for (i = length(full); i < W; i++) full = " " full; return full
        }
        col = (pct > 0) ? "\033[1;31m" : "\033[1;34m"
        ptag = (pct > 0) ? sprintf("(+%d%%)", pct) : sprintf("(%d%%)", pct)
        full = str " " ptag
        for (i = length(full); i < W; i++) full = " " full
        return col full RST
    }
    BEGIN {
        loadcyc(log44b, "b44"); loadcyc(log65b, "b65")
        for (i = 0; i <= 5; i++) {
            loadcyc(tmpdir "/m" i "_44.log", "m" i "44")
            loadcyc(tmpdir "/m" i "_65.log", "m" i "65")
        }
        lbl[0] = "Step1 RHOPRIME  (real)"
        lbl[1] = "Step2 CS1       (real)"
        lbl[2] = "Step3 CS2_CT0   (real)"
        lbl[3] = "Step4 Y_SAMPLE  (emu) "
        lbl[4] = "Step5 CHKNORM   (emu) "
        lbl[5] = "Step6 BA        (emu) "
        SEP = "  ─────────────────────────────────────────────────────────────────────────────────────────────────"
        HDR = "  %-26s  %-6s  %14s  %14s  %14s  %14s\n"
        printf "  SCA masking overhead — sign_internal / verify_internal  (est ms @70MHz×75)\n"
        print SEP
        printf HDR, "", "",         "sign_int",  "sign_int",  "vrfy_int",  "vrfy_int"
        printf HDR, "Step", "Metric", "ML-DSA-44", "ML-DSA-65", "ML-DSA-44", "ML-DSA-65"
        print SEP
        bsi44c = cyc("b44","sign_internal");    bsi65c = cyc("b65","sign_internal")
        bvi44c = cyc("b44","verify_internal");  bvi65c = cyc("b65","verify_internal")
        bsi44s = d["b44","sign_internal","stack"];   bsi65s = d["b65","sign_internal","stack"]
        bvi44s = d["b44","verify_internal","stack"]; bvi65s = d["b65","verify_internal","stack"]
        printf HDR, "baseline (no mask)", "est ms",
            estms_str(bsi44c), estms_str(bsi65c), estms_str(bvi44c), estms_str(bvi65c)
        printf HDR, "", "stack",
            comma_str(bsi44s), comma_str(bsi65s), comma_str(bvi44s), comma_str(bvi65s)
        print SEP
        for (i = 0; i <= 5; i++) {
            p44 = "m" i "44"; p65 = "m" i "65"
            si44c = cyc(p44,"sign_internal");   si65c = cyc(p65,"sign_internal")
            vi44c = cyc(p44,"verify_internal"); vi65c = cyc(p65,"verify_internal")
            si44s = d[p44,"sign_internal","stack"]; si65s = d[p65,"sign_internal","stack"]
            vi44s = d[p44,"verify_internal","stack"]; vi65s = d[p65,"verify_internal","stack"]
            if (si44c == 0 && si65c == 0) {
                printf "  %-26s  (build/run failed)\n", lbl[i]; continue
            }
            printf "  %-26s  %-6s  %s  %s  %s  %s\n", lbl[i], "est ms",
                fmt_cell(estms_str(si44c), si44c, bsi44c),
                fmt_cell(estms_str(si65c), si65c, bsi65c),
                fmt_cell(estms_str(vi44c), vi44c, bvi44c),
                fmt_cell(estms_str(vi65c), vi65c, bvi65c)
            printf "  %-26s  %-6s  %s  %s  %s  %s\n", "", "stack",
                fmt_cell(comma_str(si44s), si44s, bsi44s),
                fmt_cell(comma_str(si65s), si65s, bsi65s),
                fmt_cell(comma_str(vi44s), vi44s, bvi44s),
                fmt_cell(comma_str(vi65s), vi65s, bvi65s)
        }
        print SEP; printf "\n"
    }
    ' /dev/null

    rm -rf "$tmpdir"

    # ── ML-KEM-768 cycle/stack measurement ─────────────────────────
    hr
    ok "Measuring ML-KEM-768 ($tc_label) ..."
    local log_kem elf_kem
    if [ "$HOST_ROLE" = delivery ]; then
        elf_kem="$OUT_DIR/mlkem768_test_armclang.elf"
    else
        elf_kem="$OUT_DIR/mlkem768_test.elf"
    fi
    (cd "$IMPL_DIR" && make -B -f $mk build_kem768 "${make_args[@]}" -s >/dev/null 2>&1) \
        && {
            log_kem="$OUT_DIR/log/perfkem768_${tc_label}_${ts}.log"
            "$QEMU" -M mps2-an385 -nographic -semihosting -kernel "$elf_kem" >"$log_kem" 2>&1
            echo
            awk -v f="$log_kem" '
            function estms(cyc,   v,s,r) {
                if (cyc+0 == 0) return "-"
                v = int(cyc * 75 / 70000 + 0.5); s = sprintf("%d", v); r = ""
                while (length(s) > 3) { r = "," substr(s, length(s)-2) r; s = substr(s, 1, length(s)-3) }
                return s r " ms"
            }
            function comma(n,   s,r) {
                n = int(n); if (n == 0) return "-"; s = sprintf("%d", n); r = ""
                while (length(s) > 3) { r = "," substr(s, length(s)-2) r; s = substr(s, 1, length(s)-3) }
                return s r
            }
            {
                if (match($0, /^MLKEM768,(stack|cycles),(keypair|encaps|decaps):$/)) {
                    tag = $0
                    getline v
                    d[tag] = v + 0
                }
            }
            END {
                SEP = "  ────────────────────────────────────────────────────────────────"
                printf "  ML-KEM-768 (%s)\n", "'"$tc_label"'"
                print SEP
                printf "  %-10s %12s %12s %12s\n", "Operation", "cycles", "est ms", "stack"
                print SEP
                split("keypair encaps decaps", ops, " ")
                for (i = 1; i <= 3; i++) {
                    op = ops[i]
                    ck = "MLKEM768,cycles," op ":"
                    sk = "MLKEM768,stack," op ":"
                    printf "  %-10s %12s %12s %12s\n", op, comma(d[ck]), estms(d[ck]), comma(d[sk])
                }
                print SEP
            }' "$log_kem"
        } || warn "ML-KEM-768 build/run failed — skipped"

    pause
}

action_qemu_lib() {
    local mk=Makefile.gcc
    choose_masking
    echo
    if ! check_gnu_tc; then err "GNU_TC missing: $GNU_TC"; pause; return; fi
    if ! check_qemu;   then err "QEMU missing: $QEMU";     pause; return; fi

    title "QEMU via-library test — test harness links debug .a only"
    dim  "Uses libmldsa_sc300_gcc_le_long_dbg.lib (BUILD=debug)."
    dim  "Release .a is stripped; never exposed to the test harness."
    hr
    (cd "$IMPL_DIR" && \
        make -f $mk              clean     >/dev/null 2>&1 ; \
        make -f Makefile.gcc.lib clean-all >/dev/null 2>&1 ; \
        make -f $mk build_lib EXTRA_CFLAGS="$CHOSEN_MASK" GNU_TC="$GNU_TC" QEMU="$QEMU") \
        || { err "Build failed."; pause; return; }
    echo
    (cd "$IMPL_DIR" && make -f $mk qemu_lib GNU_TC="$GNU_TC" QEMU="$QEMU") \
        || { err "QEMU run failed."; pause; return; }
    show_artifacts "Produced artifacts" \
        libmldsa_sc300_gcc_le_long_dbg.lib \
        mldsa65_test_via_lib.elf
    print_hint "re-run QEMU without rebuilding" \
        "cd $IMPL_DIR" \
        "make -f Makefile.gcc qemu_lib GNU_TC=\"$GNU_TC\" QEMU=\"$QEMU\""
    print_hint "inspect the debug archive" \
        "$GNU_TC/bin/arm-none-eabi-nm $OUT_DIR/libmldsa_sc300_gcc_le_long_dbg.lib | less" \
        "$GNU_TC/bin/arm-none-eabi-readelf -S $OUT_DIR/libmldsa_sc300_gcc_le_long_dbg.lib"
    pause
}

action_qemu_armclang() {
    local mk=Makefile.armclang
    choose_masking
    echo
    if ! check_armclang; then err "ARMCLANG missing: $ARMCLANG"; pause; return; fi
    if ! check_qemu;     then err "QEMU missing: $QEMU";         pause; return; fi

    title "QEMU test — armclang-built"
    hr
    (cd "$IMPL_DIR" && \
        make -f $mk clean >/dev/null 2>&1 && \
        PATH="$(dirname "$ARMCLANG"):$PATH" \
        make -f $mk build EXTRA_CFLAGS="$CHOSEN_MASK" QEMU="$QEMU") \
        || { err "Build failed."; pause; return; }
    echo
    (cd "$IMPL_DIR" && \
        PATH="$(dirname "$ARMCLANG"):$PATH" \
        make -f $mk qemu QEMU="$QEMU") \
        || { err "QEMU run failed."; pause; return; }
    show_artifacts "Produced artifacts" \
        mldsa65_test_armclang.elf mldsa65_test_armclang.bin mldsa65_test_armclang.map
    print_hint "re-run without rebuilding" \
        "cd $IMPL_DIR" \
        "PATH=$(dirname "$ARMCLANG"):\$PATH make -f Makefile.armclang qemu QEMU=\"$QEMU\""
    pause
}

action_lib_gcc() {
    local be enum wchar opt build
    be=$(ask    "BE (big-endian) 0|1"             "0")
    enum=$(ask  "ENUM short|long"                 "long")
    wchar=$(ask "WCHAR 16|32"                      "32")
    opt=$(ask   "OPT -O0|-O1|-O2|-O3|-Os"          "-O2")
    build=$(ask "BUILD release|debug"             "release")
    choose_masking
    if ! check_gnu_tc; then err "GNU_TC missing: $GNU_TC"; pause; return; fi

    title "GCC library build — BE=$be ENUM=$enum WCHAR=$wchar OPT=$opt BUILD=$build"
    hr
    (cd "$IMPL_DIR" && \
        make -f Makefile.gcc.lib clean-all >/dev/null 2>&1 && \
        make -f Makefile.gcc.lib BE=$be ENUM=$enum WCHAR=$wchar OPT="$opt" BUILD=$build \
            MASK_CFLAGS="$CHOSEN_MASK" GNU_TC="$GNU_TC") \
        || { err "Build failed."; pause; return; }

    local endian_tag build_tag enum_tag wchar_tag opt_tag lib_name
    [ "$be" = "1" ] && endian_tag=be || endian_tag=le
    [ "$build" = "debug" ] && build_tag="_dbg" || build_tag=""
    [ "$wchar" = "16" ] && wchar_tag="_w16" || wchar_tag=""
    [ "$opt" = "-O2" ] && opt_tag="" || opt_tag="_${opt#-}"
    enum_tag="$enum"
    lib_name="libmldsa_sc300_gcc_${endian_tag}_${enum_tag}${wchar_tag}${opt_tag}${build_tag}.lib"

    show_artifacts "Produced library" "$lib_name"
    echo
    dim "symbols / sections (first 5 .o in archive):"
    (cd "$IMPL_DIR" && "$GNU_TC/bin/arm-none-eabi-ar" t "$lib_name" 2>/dev/null | head -5 | sed 's/^/    /')

    print_hint "link from a caller" \
        "$GNU_TC/bin/arm-none-eabi-gcc -I$IMPL_DIR my_app.c $OUT_DIR/$lib_name -o my_app.elf"
    print_hint "use public header" \
        "#include \"mldsa65_sc300.h\""
    pause
}

action_lib_armclang() {
    local be enum wchar opt build
    be=$(ask    "BE (big-endian) 0|1"             "0")
    enum=$(ask  "ENUM short|long"                 "long")
    wchar=$(ask "WCHAR 16|32"                      "32")
    opt=$(ask   "OPT -O0|-O1|-O2|-O3|-Os"          "-O2")
    build=$(ask "BUILD release|debug"             "release")
    choose_masking
    if ! check_armclang; then err "ARMCLANG missing: $ARMCLANG"; pause; return; fi

    title "armclang library build — BE=$be ENUM=$enum WCHAR=$wchar OPT=$opt BUILD=$build"
    hr
    (cd "$IMPL_DIR" && \
        make -f Makefile.armclang.lib clean-all >/dev/null 2>&1 && \
        PATH="$(dirname "$ARMCLANG"):$PATH" \
        make -f Makefile.armclang.lib BE=$be ENUM=$enum WCHAR=$wchar OPT="$opt" BUILD=$build \
            MASK_CFLAGS="$CHOSEN_MASK") \
        || { err "Build failed."; pause; return; }

    local endian_tag build_tag wchar_tag opt_tag lib_name
    [ "$be" = "1" ] && endian_tag=be || endian_tag=le
    [ "$build" = "debug" ] && build_tag="_dbg" || build_tag=""
    [ "$wchar" = "16" ] && wchar_tag="_w16" || wchar_tag=""
    [ "$opt" = "-O2" ] && opt_tag="" || opt_tag="_${opt#-}"
    lib_name="libmldsa65_sc300_${endian_tag}_${enum}${wchar_tag}${opt_tag}${build_tag}.lib"

    show_artifacts "Produced library (delivery archive)" "$lib_name"
    echo
    [ "$build" = "release" ] && \
        ok "Release archive — debug info stripped; safe to ship."
    [ "$build" = "debug" ] && \
        warn "DEBUG archive — contains DWARF; DO NOT ship."

    print_hint "link from a caller" \
        "armclang --target=arm-arm-none-eabi -mcpu=cortex-m3 -mthumb \\" \
        "  -I$IMPL_DIR -c my_app.c -o my_app.o" \
        "armlink my_app.o $OUT_DIR/$lib_name -o my_app.elf"
    print_hint "public header" \
        "#include \"mldsa65_sc300.h\""
    pause
}

# ------------------------------------------------------------------ #
# Board-preset shortcut: skip individual ABI knobs, use a known-good   #
# combination baked into the Makefile (BOARD=<name>).                 #
# ------------------------------------------------------------------ #
action_lib_board() {
    local board build
    # Only one board for now; extend list as more presets are added.
    echo "  Board presets:"
    echo "    S3SSE1A  (little-endian, enum long, wchar 16, -O0)"
    echo
    board=$(ask "Board" "S3SSE1A")
    build=$(ask "BUILD release|debug" "release")
    choose_masking
    if ! check_armclang; then err "ARMCLANG missing: $ARMCLANG"; pause; return; fi

    title "armclang library build — board=$board BUILD=$build"
    hr
    (cd "$IMPL_DIR" && \
        make -f Makefile.armclang.lib clean-all >/dev/null 2>&1 && \
        PATH="$(dirname "$ARMCLANG"):$PATH" \
        make -f Makefile.armclang.lib BOARD=$board BUILD=$build \
            MASK_CFLAGS="$CHOSEN_MASK") \
        || { err "Build failed."; pause; return; }

    # Figure out the produced archive path (must mirror Makefile.armclang.lib)
    local endian_tag enum_tag wchar_tag opt_tag build_tag lib_name
    case "$board" in
        S3SSE1A)
            endian_tag=le; enum_tag=long; wchar_tag=_w16; opt_tag=_O0 ;;
        *)
            endian_tag=le; enum_tag=long; wchar_tag=;    opt_tag= ;;
    esac
    [ "$build" = "debug" ] && build_tag="_dbg" || build_tag=""
    lib_name="libmldsa65_sc300_${endian_tag}_${enum_tag}${wchar_tag}${opt_tag}_${board}${build_tag}.lib"

    show_artifacts "Produced library (board preset: $board)" "$lib_name"
    [ "$build" = "release" ] && \
        ok "Release archive — debug info stripped; safe to ship."
    [ "$build" = "debug" ] && \
        warn "DEBUG archive — contains DWARF; DO NOT ship."

    print_hint "link from caller" \
        "armclang --target=arm-arm-none-eabi -mcpu=cortex-m3 -mthumb \\" \
        "  -I$IMPL_DIR -c my_app.c -o my_app.o" \
        "armlink my_app.o $OUT_DIR/$lib_name -o my_app.elf"
    print_hint "public header" \
        "#include \"mldsa65_sc300.h\""
    pause
}

action_lib_matrix() {
    echo
    title "Build all 4 library configs (GCC sanity)"
    hr
    if ! check_gnu_tc; then err "GNU_TC missing"; pause; return; fi
    local be enum rc log
    log=$(mktemp -t mldsa_matrix.XXXXXX)
    # First clean-all so we don't carry stale archives from prior runs.
    (cd "$IMPL_DIR" && make -f Makefile.gcc.lib clean-all >/dev/null 2>&1)
    for be in 0 1; do
        for enum in short long; do
            (cd "$IMPL_DIR" && \
                make -f Makefile.gcc.lib BE=$be ENUM=$enum GNU_TC="$GNU_TC") \
                >"$log" 2>&1
            rc=$?
            if [ $rc -eq 0 ]; then
                ok "  BE=$be ENUM=$enum  OK"
            else
                err "  BE=$be ENUM=$enum  FAIL (exit $rc)"
                echo "--- last build output ---"
                tail -n 10 "$log"
                echo "-------------------------"
            fi
        done
    done
    rm -f "$log"

    show_artifacts "Produced libraries (matrix)" \
        libmldsa_sc300_gcc_le_short.lib \
        libmldsa_sc300_gcc_le_long.lib \
        libmldsa_sc300_gcc_be_short.lib \
        libmldsa_sc300_gcc_be_long.lib
    pause
}

action_clean() {
    echo
    title "Clean all build artifacts"
    hr
    (cd "$IMPL_DIR" && \
        make -f Makefile.gcc          clean      >/dev/null 2>&1 ;  \
        make -f Makefile.armclang     clean      >/dev/null 2>&1 ;  \
        make -f Makefile.gcc.lib      clean-all  >/dev/null 2>&1 ;  \
        make -f Makefile.armclang.lib clean-all  >/dev/null 2>&1 ;  \
        true)
    ok "cleaned."
    echo
    dim "output/ contents (should be empty except .gitkeep):"
    (cd "$OUT_DIR" && ls -A 2>/dev/null | grep -v '^\.gitkeep$') \
        || dim "  (nothing)"
    pause
}

action_env() {
    echo
    title "Detected host environment"
    hr
    report_env
    echo
    dim "Override any path by exporting before launching tui.sh:"
    dim "  GNU_TC=/path   QEMU=/path   ARMCLANG=/path   tools/tui.sh"
    echo
    title "Directory layout"
    hr
    printf '  %-38s %s\n' "impl_sc300/"                          "(runtime sources)"
    printf '  %-38s %s\n' "  sc300/ ref/ cmsis/ test/ tools/"    "source trees"
    printf '  %-38s %s\n' "  mldsa65_sc300.h"                    "public caller header"
    printf '  %-38s %s\n' "  api_wrapper.c/h"                    "10-arg wrapper impl"
    printf '  %-38s %s\n' "  sources.mk"                         "shared Makefile source list"
    printf '  %-38s %s\n' "  Makefile.{gcc,armclang}"            "QEMU test builds"
    printf '  %-38s %s\n' "  Makefile.{gcc,armclang}.lib"        "library archive builds"
    echo
    printf '  %-38s %s\n' "output/"                              "all generated artefacts"
    printf '  %-38s %s\n' "  mldsa65_test.elf/.bin"                "gcc QEMU test"
    printf '  %-38s %s\n' "  mldsa65_test_armclang.elf/.bin/.map"        "armclang QEMU test"
    printf '  %-38s %s\n' "  mldsa65_test_via_lib.elf"            "library-linked test"
    printf '  %-38s %s\n' "  libmldsa65_sc300_*.lib"               "static libraries"
    printf '  %-38s %s\n' "  obj/"                               "intermediate object dirs"
    echo
    printf '  %-38s %s\n' "log/"                                 "(manually captured run logs)"
    echo
    show_artifacts "Currently present artifacts (under output/)" \
        mldsa65_test.elf mldsa65_test.bin \
        mldsa65_test_armclang.elf mldsa65_test_armclang.bin mldsa65_test_armclang.map \
        mldsa65_test_via_lib.elf \
        libmldsa_sc300_gcc_le_short.lib     libmldsa_sc300_gcc_le_long.lib \
        libmldsa_sc300_gcc_be_short.lib     libmldsa_sc300_gcc_be_long.lib \
        libmldsa_sc300_gcc_le_short_dbg.lib libmldsa_sc300_gcc_le_long_dbg.lib \
        libmldsa_sc300_gcc_be_short_dbg.lib libmldsa_sc300_gcc_be_long_dbg.lib \
        libmldsa65_sc300_le_short.lib         libmldsa65_sc300_le_long.lib \
        libmldsa65_sc300_be_short.lib         libmldsa65_sc300_be_long.lib \
        libmldsa65_sc300_le_short_dbg.lib     libmldsa65_sc300_le_long_dbg.lib \
        libmldsa65_sc300_be_short_dbg.lib     libmldsa65_sc300_be_long_dbg.lib
    pause
}

# ------------------------------------------------------------------ #
# Menus                                                                #
# ------------------------------------------------------------------ #
dev_menu() {
    while true; do
        clear
        title " impl_sc300 TUI  —  Mac dev / Claude workflow "
        hr
        printf ' host : %s (%s)\n' "$HOST_TAG" "$HOST_ROLE"
        printf ' impl : %s\n' "$IMPL_DIR"
        hr
        echo " 1) QEMU verify        ML-DSA (44+65 ACVP KAT, ~1s) ★"
        echo " 2) QEMU verify        ML-KEM-768 (KAT, 3 vectors)"
        echo " 3) Cycle/stack report (DSA + KEM)"
        echo " 4) QEMU test (gcc, direct-object build, full sequential)"
        echo " 5) QEMU test (gcc, LINKED against debug lib)"
        echo " 6) QEMU test (armclang build)"
        echo " 7) Build all 4 library configs (sanity)"
        echo " 8) Clean everything"
        echo " 9) Show detected env"
        echo " q) Quit"
        hr
        read -rp "Select: " c
        case "$c" in
            1) action_qemu_full ;;
            2) action_qemu_kem768 ;;
            3) action_perf_report ;;
            4) action_qemu_test ;;
            5) action_qemu_lib ;;
            6) action_qemu_armclang ;;
            7) action_lib_matrix ;;
            8) action_clean ;;
            9) action_env ;;
            q|Q) exit 0 ;;
        esac
    done
}

delivery_menu() {
    while true; do
        clear
        title " impl_sc300 TUI  —  Ubuntu delivery workflow "
        hr
        printf ' host : %s (%s)\n' "$HOST_TAG" "$HOST_ROLE"
        printf ' impl : %s\n' "$IMPL_DIR"
        hr
        echo " [Delivery (Ubuntu)]"
        echo "  1) Build library  for board preset (S3SSE1A, …) ★"
        echo "  2) Build library  (armclang, custom ABI knobs)"
        echo "  3) Build library  (GCC sanity)"
        echo "  4) Build all 4 library configs (matrix)"
        echo "  5) QEMU verify    ML-DSA (44+65 ACVP KAT) ★"
        echo "  6) QEMU verify    ML-KEM-768 (KAT, 3 vectors)"
        echo "  7) Cycle/stack report (DSA + KEM)"
        echo
        echo " [Mac 개발용 (Ubuntu에서도 동작)]"
        echo "  8) QEMU via-library test (links debug .a)"
        echo "  9) QEMU test   (gcc direct-object build)"
        echo "  a) QEMU test   (armclang build)"
        echo
        echo "  c) Clean everything"
        echo "  e) Show detected env"
        echo "  q) Quit"
        hr
        read -rp "Select: " c
        case "$c" in
            1) action_lib_board ;;
            2) action_lib_armclang ;;
            3) action_lib_gcc ;;
            4) action_lib_matrix ;;
            5) action_qemu_full ;;
            6) action_qemu_kem768 ;;
            7) action_perf_report ;;
            8) action_qemu_lib ;;
            9) action_qemu_test ;;
            a|A) action_qemu_armclang ;;
            c|C) action_clean ;;
            e|E) action_env ;;
            q|Q) exit 0 ;;
        esac
    done
}

# ------------------------------------------------------------------ #
main() {
    case "$HOST_ROLE" in
        dev)      dev_menu ;;
        delivery) delivery_menu ;;
        *)
            warn "Unknown host '$HOST_TAG'. Using delivery menu."
            delivery_menu
            ;;
    esac
}

main "$@"

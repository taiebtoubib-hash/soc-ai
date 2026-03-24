"""
training/pipeline.py
--------------------
Full ML Pipeline Orchestrator

Runs all 6 pipeline steps in sequence:
  01_collect  → 02_prepare → 03_train → 04_evaluate → 05_promote → 06_monitor

Step failures are caught and reported clearly.
The pipeline keeps going after non-critical steps (e.g., if candidate
doesn't beat production in step 4, it logs the reason and stops gracefully).

Run:
  python training/pipeline.py               # full run with CV
  python training/pipeline.py --skip-cv     # skip cross-validation (faster)
  python training/pipeline.py --dry-run     # print what would run, but don't execute
  python training/pipeline.py --from-step 3 # start from step 3 (skip collect+prepare)
  python training/pipeline.py --stop-after 4 # run steps 1-4 only
"""

import argparse
import subprocess
import sys
import os
import time

# Pipeline step definitions
STEPS = [
    (1, "01_collect.py",  "Collect & Merge Data"),
    (2, "02_prepare.py",  "Prepare Features"),
    (3, "03_train.py",    "Train Models"),
    (4, "04_evaluate.py", "Evaluate Candidate vs Production"),
    (5, "05_promote.py",  "Promote Candidate to Production"),
    (6, "06_monitor.py",  "Monitor Production Health"),
]

# Exit codes from steps that mean "stop, but don't treat as fatal error"
SOFT_STOP_EXIT_CODES = {
    4: [2],   # step 04 exits 2 = production is better → don't promote
    5: [2],   # step 05 exits 2 = kept production → that's OK
    6: [1],   # step 06 exits 1 = drift detected → warn but don't crash pipeline
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SOC AI — Full ML Training Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python training/pipeline.py
  python training/pipeline.py --skip-cv
  python training/pipeline.py --from-step 3 --stop-after 5
  python training/pipeline.py --dry-run
        """,
    )
    p.add_argument("--skip-cv",     action="store_true", dest="skip_cv",
                   help="Skip cross-validation in step 03 (faster).")
    p.add_argument("--no-smote",    action="store_true", dest="no_smote",
                   help="Disable SMOTE oversampling in step 02.")
    p.add_argument("--from-step",   type=int, default=1, dest="from_step",
                   help="Start from this step number (1-6).")
    p.add_argument("--stop-after",  type=int, default=6, dest="stop_after",
                   help="Stop after this step number (1-6).")
    p.add_argument("--dry-run",     action="store_true", dest="dry_run",
                   help="Print steps that would be run without executing them.")
    return p.parse_args()


def build_step_args(step_num: int, args: argparse.Namespace) -> list:
    """Build extra CLI args to pass to each specific step script."""
    extra: list = []
    if step_num == 2 and args.no_smote:
        extra += ["--no-smote"]
    if step_num == 3 and args.skip_cv:
        extra += ["--skip-cv"]
    return extra


def run_step(step_num: int, script: str, label: str,
             extra_args: list, dry_run: bool) -> int:
    """Execute one pipeline step as a subprocess. Returns its exit code."""
    script_path = os.path.join(os.path.dirname(__file__), script)
    cmd = [sys.executable, script_path] + extra_args

    bar = "─" * 60
    print(f"\n{bar}")
    print(f"  STEP {step_num:02d} — {label.upper()}")
    print(f"{bar}")

    if dry_run:
        print(f"  [DRY-RUN] Would run: {' '.join(cmd)}")
        return 0

    t0 = time.perf_counter()
    result = subprocess.run(cmd)
    elapsed = time.perf_counter() - t0

    code = result.returncode
    status = "✅ OK" if code == 0 else (f"⚠️  exit({code})" if code in SOFT_STOP_EXIT_CODES.get(step_num, []) else f"❌ FAILED (exit {code})")
    print(f"\n  {status}  [{elapsed:.1f}s]")
    return code


def main() -> None:
    args = parse_args()

    print("=" * 60)
    print("  SOC AI — ML PIPELINE")
    mode_tag = " [DRY-RUN]" if args.dry_run else ""
    print(f"  Steps {args.from_step}–{args.stop_after}{mode_tag}")
    print("=" * 60)

    pipeline_start = time.perf_counter()
    results: list[tuple[int, str, int]] = []   # (step_num, label, exit_code)

    for step_num, script, label in STEPS:
        # Range filter
        if step_num < args.from_step:
            continue
        if step_num > args.stop_after:
            break

        extra = build_step_args(step_num, args)
        code  = run_step(step_num, script, label, extra, args.dry_run)
        results.append((step_num, label, code))

        # Soft stop: gracefully halt without error
        if code in SOFT_STOP_EXIT_CODES.get(step_num, []):
            print(f"\n  Pipeline halting gracefully at step {step_num} (soft stop).")
            break

        # Hard stop: unexpected failure
        if code not in (0,):
            print(f"\n  ❌  Pipeline aborted at step {step_num} — exit code {code}.")
            print("  Fix the error above and re-run from: "
                  f"python training/pipeline.py --from-step {step_num}")
            sys.exit(code)

    elapsed_total = time.perf_counter() - pipeline_start
    print("\n" + "=" * 60)
    print("  PIPELINE SUMMARY")
    print("=" * 60)
    for sn, lbl, code in results:
        tag = "✅" if code == 0 else ("⚠️ " if code in SOFT_STOP_EXIT_CODES.get(sn, []) else "❌")
        print(f"  {tag}  Step {sn:02d}: {lbl}")
    print(f"\n  Total time: {elapsed_total:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()

"""Shared execution, guarded source mutations and benchmark summaries."""

import statistics
import subprocess


def make_runner(root, output, suffix="", *, env=None, timeout=None):
    def run(command, log, expected=None):
        result = subprocess.run(command, cwd=root, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout)
        (output / (log + suffix)).write_text(result.stdout)
        if expected is None:
            if result.returncode:
                raise RuntimeError(f"{log}: {result.stdout}")
        elif result.returncode == 0 or expected not in result.stdout:
            raise RuntimeError(f"mutation did not fail the expected assertion: {log}: {result.stdout}")
        return result.stdout
    return run


def replace(text, old, new, count=1, context=""):
    found = text.count(old)
    if found != count:
        raise RuntimeError(f"stale mutation: {context}: expected {count} matches, found {found}: {old}")
    return text.replace(old, new)


def medians(samples):
    if isinstance(samples, dict):
        return {key: medians(values) for key, values in samples.items()}
    if samples and isinstance(samples[0], dict):
        return {unit: statistics.median(value[unit] for value in samples) for unit in samples[0]}
    return statistics.median(samples)

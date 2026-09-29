"""Provision native test resources without changing application runtime limits."""
import sys
import os
import subprocess
from contextlib import contextmanager


def prepare():
    if sys.platform != 'darwin':
        return
    import resource
    # The overlay fixture hosts 24 complete nodes in one process. The macOS
    # shell default of 256 descriptors can exhaust sockets during admission.
    required = 8192
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY or soft >= required:
        return
    if hard != resource.RLIM_INFINITY and hard < required:
        raise RuntimeError('Native overlay qualification requires 8192 file descriptors; hard limit is ' + str(hard))
    resource.setrlimit(resource.RLIMIT_NOFILE, (required, hard))
    actual = resource.getrlimit(resource.RLIMIT_NOFILE)
    if actual[0] != resource.RLIM_INFINITY and actual[0] < required:
        raise RuntimeError('Native file-descriptor reservation was not applied')
    print('Native test file-descriptor limits:', (soft, hard), '->', actual, flush=True)


@contextmanager
def disposable_mac_ports():
    """Give the co-located overlay its port budget only on disposable CI Macs.

    The real 24-node fixture exhausts the default 49152..65535 range. Preserve
    all test assertions and application limits; restore host state even when
    the child test fails. Personal Macs and every other platform are untouched.
    """
    if sys.platform != 'darwin' or os.environ.get('GITHUB_ACTIONS') != 'true':
        yield
        return
    key = 'net.inet.ip.portrange.first'
    def current():
        return int(subprocess.check_output(['sysctl', '-n', key], text=True).strip())
    original = current()
    if not 1024 <= original <= 65535:
        raise RuntimeError('Unexpected native test ephemeral port range')
    if original <= 10240:
        yield
        return
    try:
        subprocess.run(['sudo', 'sysctl', '-w', key + '=10240'], check=True)
        if current() != 10240:
            raise RuntimeError('Native test ephemeral port reservation was not applied')
        print('Disposable Mac test ephemeral first port:', original, '->', 10240, flush=True)
        yield
    finally:
        subprocess.run(['sudo', 'sysctl', '-w', key + '=' + str(original)], check=True)
        if current() != original:
            raise RuntimeError('Native test ephemeral port range was not restored')
        print('Disposable Mac test ephemeral first port restored:', original, flush=True)

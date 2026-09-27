"""Provision native test resources without changing application runtime limits."""
import sys


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

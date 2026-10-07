# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Single Kernel Library."""

import warnings

# `google.api_core` emits a FutureWarning at import time when the running Python is
# approaching (or past) its upstream EOL so the warning fires on every hook and
# leaks into `juju run` action output. On the ubuntu@22.04 base the charm runs on
# Python 3.10 and we cannot upgrade while that base is supported, so the
# warning carries no action for the operator reading that output.
# Drop this once the ubuntu@22.04 base is gone and the charm runs on Python >= 3.11.
warnings.filterwarnings(
    "ignore",
    message=r"You are using a (non-supported )?Python version",
    category=FutureWarning,
)

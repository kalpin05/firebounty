import os
import shutil


def get_tool(tool_name):
    """
    Resolve preferred tool location.

    Priority:

    1. ~/go/bin
    2. /root/go/bin
    3. PATH

    Raises Exception if tool not found.
    """

    home_go = os.path.expanduser(
        f"~/go/bin/{tool_name}"
    )

    root_go = f"/root/go/bin/{tool_name}"

    candidates = [

        home_go,

        root_go,

        shutil.which(tool_name)

    ]

    for candidate in candidates:

        if candidate and os.path.exists(candidate):

            return candidate

    raise FileNotFoundError(
        f"{tool_name} not found"
    )
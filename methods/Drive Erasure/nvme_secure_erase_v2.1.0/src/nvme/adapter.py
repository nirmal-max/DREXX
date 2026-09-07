def build_command(controller,action):
    code={"block":"0x02","overwrite":"0x03","crypto":"0x04"}[action]
    return ["nvme","sanitize",controller,f"--sanact={code}","--wait"]
def build_log_command(controller): return ["nvme","sanitize-log",controller,"-o","json"]

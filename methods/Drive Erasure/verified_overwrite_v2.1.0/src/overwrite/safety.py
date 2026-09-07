def guard(device, execute=False):
    if device.mounted: raise RuntimeError("mounted target")
    if device.system_disk: raise RuntimeError("system disk")
    if execute and not isinstance(device.path,str): raise RuntimeError("invalid target")
    return True

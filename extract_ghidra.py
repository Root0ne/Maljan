import zipfile
zipfile.ZipFile("/opt/ghidra_12.0.4.zip").extractall("/opt/")
print("Extracted to /opt/")

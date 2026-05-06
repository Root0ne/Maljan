#!/bin/bash
set -e
GHIDRA=/opt/ghidra_12.0.4_PUBLIC

install_jar() {
  local artifact=$1
  local relpath=$2
  local jarpath="$GHIDRA/$relpath"
  if [ -f "$jarpath" ]; then
    mvn -q install:install-file -Dfile="$jarpath" -DgroupId=ghidra -DartifactId="$artifact" -Dversion=12.0.4 -Dpackaging=jar -DgeneratePom=true
    echo "Installed: $artifact"
  else
    echo "MISSING: $jarpath"
  fi
}

install_jar Base "Ghidra/Features/Base/lib/Base.jar"
install_jar Decompiler "Ghidra/Features/Decompiler/lib/Decompiler.jar"
install_jar Docking "Ghidra/Framework/Docking/lib/Docking.jar"
install_jar Generic "Ghidra/Framework/Generic/lib/Generic.jar"
install_jar Project "Ghidra/Framework/Project/lib/Project.jar"
install_jar SoftwareModeling "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar"
install_jar Utility "Ghidra/Framework/Utility/lib/Utility.jar"
install_jar Gui "Ghidra/Framework/Gui/lib/Gui.jar"
install_jar FileSystem "Ghidra/Framework/FileSystem/lib/FileSystem.jar"
install_jar Graph "Ghidra/Framework/Graph/lib/Graph.jar"
install_jar DB "Ghidra/Framework/DB/lib/DB.jar"
install_jar Emulation "Ghidra/Framework/Emulation/lib/Emulation.jar"
install_jar PDB "Ghidra/Features/PDB/lib/PDB.jar"
install_jar FunctionID "Ghidra/Features/FunctionID/lib/FunctionID.jar"
install_jar Help "Ghidra/Framework/Help/lib/Help.jar"
install_jar Debugger-api "Ghidra/Debug/Debugger-api/lib/Debugger-api.jar"
install_jar Framework-TraceModeling "Ghidra/Debug/Framework-TraceModeling/lib/Framework-TraceModeling.jar"
install_jar Debugger-rmi-trace "Ghidra/Debug/Debugger-rmi-trace/lib/Debugger-rmi-trace.jar"

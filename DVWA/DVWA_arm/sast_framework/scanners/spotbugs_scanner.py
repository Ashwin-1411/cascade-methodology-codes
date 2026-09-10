import os
import tempfile
import xml.etree.ElementTree as ET
from sast_framework.utils.runner import run_command


def run_spotbugs(target):
    # Determine the path to the downloaded SpotBugs JAR
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Path based on previous dir / results
    spotbugs_jar = os.path.join(base_dir, "spotbugs_home", "spotbugs-4.8.6", "lib", "spotbugs.jar")
    
    if not os.path.exists(spotbugs_jar):
        print(f"[!] SpotBugs JAR not found at {spotbugs_jar}")
        return []

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    output_path = temp_file.name
    temp_file.close() # Close so spotbugs can write to it

    # SpotBugs needs .class files. We target the target_code directory
    # where Vuln.class already exists.
    # Use -xml:withMessages for detailed XML output
    cmd = [
        "java",
        "-jar", spotbugs_jar,
        "-textui",
        "-xml:withMessages",
        "-output", output_path,
        target
    ]
    
    print(f"[*] Executing SpotBugs: {' '.join(cmd)}")
    run_command(cmd)

    findings = []
    try:
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            tree = ET.parse(output_path)
            root = tree.getroot()
            for bug in root.findall('BugInstance'):
                source_line = bug.find('SourceLine')
                findings.append({
                    "type": bug.get('type'),
                    "category": bug.get('category'),
                    "priority": bug.get('priority'),
                    "message": bug.find('LongMessage').text if bug.find('LongMessage') is not None else "",
                    "file": source_line.get('sourcepath') if source_line is not None else "",
                    "line": source_line.get('start') if source_line is not None else ""
                })
    except Exception as e:
        print(f"Error parsing SpotBugs XML: {e}")
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)
            
    return findings
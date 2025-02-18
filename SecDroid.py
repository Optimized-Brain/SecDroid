import logging
import shutil
import os
import sys
import glob
import time
import hashlib
import subprocess
import platform
import re
import pathlib

# Global logger instance
logger = logging.getLogger("SecDroidLogger")

def SecDroid_core_log(apk_path):
    """Initialize global logging if the -l flag is passed."""

    if "-l" not in sys.argv:
        return  # Do nothing if logging is not enabled

    # Get timestamp and APK filename
    ctime = time.strftime("%Y-%m-%d_%H-%M-%S")
    apk_file_name = os.path.splitext(os.path.basename(apk_path))[0]

    # Define log file path
    log_file_path = os.path.join(os.path.dirname(apk_path), f"SecDroid_{apk_file_name}_{ctime}.txt")

    # Configure logger
    logger.setLevel(logging.INFO)

    # Remove existing handlers (prevents duplicate logs)
    if logger.hasHandlers():
        logger.handlers.clear()

    # File handler
    file_handler = logging.FileHandler(log_file_path, mode='w')
    file_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    logger.info("======================================")
    logger.info(f"SecDroid Logging Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Log File: {log_file_path}")
    logger.info("======================================")

color_blue_bold = "\033[1;34m"
color_reset = "\033[0m"

def SecDroid_Intro(logger=None):
    
    print(color_blue_bold + r"""
     _______. _______   ______  _______  .______        ______    __   _______  
    /       ||   ____| /      ||       \ |   _  \      /  __  \  |  | |       \ 
   |   (----`|  |__   |  ,----'|  .--.  ||  |_)  |    |  |  |  | |  | |  .--.  |
    \   \    |   __|  |  |     |  |  |  ||      /     |  |  |  | |  | |  |  |  |
.----)   |   |  |____ |  `----.|  '--'  ||  |\  \----.|  `--'  | |  | |  '--'  |
|_______/    |_______| \______||_______/ | _| `._____| \______/  |__| |_______/ 
                                                                                
    ------------------------------------------------
    OWASP MASVS Static Analyzer - CoE CNDS Lab Project                               
    """ + color_reset)

    # Log the intro message if logging is enabled
    if logger is not None:
        logger.info("[+] SecDroid - a comprehensive static code analysis tool for Android apps")
        logger.info("[+] Based on: OWASP MASVS - https://mobile-security.gitbook.io/masvs/")
        logger.info("[+] Author - Shoaib Attar")
        logger.info("[*] Connect: Feel free to give feedback.")



def SecDroid_basic_req_checks():

    if platform.system() != "Linux":
        SecDroid_Intro()
        print("\n[+] Checking if APKHunt is being executed on Linux OS or not...")
        print("[!] Linux OS has not been identified! \n[!] Exiting...")
        print("\n[+] It is recommended to execute APKHunt on Kali Linux OS.")
        sys.exit(0)


    required_utilities = {
        "grep": {
            "message": "grep utility has not been observed. Kindly install it first!",
            "install": "sudo apt install grep -y"
        },
        "jadx": {
            "message": "jadx decompiler has not been observed. Kindly install it first!",
            "install": "wget https://github.com/skylot/jadx/releases/latest/download/jadx.zip && unzip jadx.zip -d jadx && sudo mv jadx /opt/"
        },
        "d2j-dex2jar": {
            "message": "dex2jar has not been observed. Kindly install it first!",
            "install": "wget https://github.com/pxb1988/dex2jar/releases/latest/download/dex-tools.zip && unzip dex-tools.zip -d dex-tools && sudo mv dex-tools /opt/"
        }
    }

    for utility, details in required_utilities.items():
        if shutil.which(utility) is None:
            SecDroid_Intro()
            print(f"\n[!] {details['message']} \n[!] Install using:\n    {details['install']}\n[!] Exiting...")
            exit(0)


def SecDroid_help():
    color_brown = "\033[0;33m"
    color_reset = "\033[0m"

    print(color_brown + "\n    SecDroid Usage:" + color_reset)
    print("\t  python3 SecDroid.py [options] {.apk file}")

    print(color_brown + "\n    Options:" + color_reset)
    print("\t -h     For help")
    print("\t -p     Provide a single APK file path")
    print("\t -m     Provide the folder path for multiple APK scanning")
    print("\t -l     Enable logger (outputs to a .txt file)")

    print(color_brown + "\n    Examples:" + color_reset)
    print("\t python3 SecDroid.py -p /Downloads/android_app.apk")
    print("\t python3 SecDroid.py -p /Downloads/android_app.apk -l")
    print("\t python3 SecDroid.py -m /Downloads/android_apps/")
    print("\t python3 SecDroid.py -m /Downloads/android_apps/ -l")

    print(color_brown + "\n    Note:" + color_reset)
    print("\t - Ensure required tools (jadx, dex2jar, grep, etc.) are installed!")

def SecDroid_core(apkpath, logger=None):

    import shutil
    import os
    import sys
    import glob
    import time
    import hashlib
    import subprocess
    import platform
    import re
    import pathlib

    if logger is None:
        logging.basicConfig(
            level=logging.INFO,  # Set the logging level to INFO
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')  # Define log message format
        logger = logging.getLogger("SecDroidLogger")
        logger.addHandler(logging.NullHandler()) 
        
        

    """Perform core analysis and log activities using the global logger."""

    exported_count = 0
    nwSecConf_final = " "
    # APK filepath check
    if not os.path.exists(apkpath):
        logger.error(f"\n[!] Given file-path '{apkpath}' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...")
        exit(0)
        
    if not apkpath.endswith(".apk"):
        logger.error(f"\n[!] Given file '{apkpath}' does not seem to be an APK file. \n[!] Kindly verify the file! \n[!] Exiting...")
        exit(0)
    
    start_time = time.time()
    logger.info(f"\n[+] Scan has been started at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")
    
    # APK filepath analysis
    apkpathbase = os.path.basename(apkpath)
    logger.info(f"[+] APK Base: {apkpathbase}")
    
    file_size = os.stat(apkpath).st_size
    kilobytes = file_size / 1024.0
    megabytes = kilobytes / 1024.0
    logger.info(f"[+] APK Size: {megabytes:.2f} MB")
    
    apkpathdir = os.path.dirname(apkpath) + "/"
    logger.info(f"[+] APK Directory: {apkpathdir}")
    apkname = os.path.splitext(apkpathbase)[0]
    
    # Check if APK name is alphanumeric (with dash or underscore allowed)
    if not re.match(r'^[a-zA-Z0-9_-]*$', apkname):
        logger.error("[!] Only Alphanumeric string with/without underscore/dash is accepted as APK file-name. Please rename the APK file.")
        exit(0)
    
    apkoutpath = os.path.join(apkpathdir, apkname)
    dex2jarpath = f"{apkoutpath}.jar"
    jadxpath = f"{apkoutpath}_SAST/"
    logger.info(f"[+] APK Static Analysis Path: {jadxpath}")
    
    # APK Hash calculation
    with open(apkpath, "rb") as f:
        file_hash = f.read()
    md5_hash = hashlib.md5(file_hash).hexdigest()
    sha256_hash = hashlib.sha256(file_hash).hexdigest()
    logger.info(f"[+] APK Hash: MD5: {md5_hash}")
    logger.info(f"[+] APK Hash: SHA256: {sha256_hash}")
    
    logger.info(f"\n[+] d2j-dex2jar has started converting APK to Java JAR file")
    logger.info("[+] =======================================================")
    try:
        # Run d2j-dex2jar
        cmd_apk_dex2jar = subprocess.run(
            ["d2j-dex2jar", apkpath, "-f", "-o", dex2jarpath],
            capture_output=True, text=True
        )
        logger.info(cmd_apk_dex2jar.stdout)
        if cmd_apk_dex2jar.stderr:
            logger.error(cmd_apk_dex2jar.stderr)
    except Exception as e:
        logger.error(f"Error running d2j-dex2jar: {e}")
    
    logger.info(f"[+] Jadx has started decompiling the application")
    logger.info("[+] ============================================")
    try:
        # Run Jadx
        cmd_apk_jadx = subprocess.run(
            ["jadx", "--deobf", apkpath, "-d", jadxpath],
            capture_output=True, text=True
        )
        logger.info(cmd_apk_jadx.stdout)
        if cmd_apk_jadx.stderr:
            logger.error(cmd_apk_jadx.stderr)
    except Exception as e:
        logger.error(f"Error running Jadx: {e}")
    
    and_manifest_path = os.path.join(jadxpath, "resources/AndroidManifest.xml")
    
    logger.info(f"\n[+] Capturing the data from the AndroidManifest file")
    logger.info("[+] ================================================")
    
    logger.info("\n==>> The Basic Information...\n")
    try:
        cmd_and_pkg_nm = subprocess.check_output(
            ["grep", "-i", "package", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        package_name = re.search(r'package=".*?"', cmd_and_pkg_nm)
        if package_name:
            logger.info(f"   {package_name.group()}")
        else:
            logger.warning("    - Package Name has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - Package Name has not been observed.")

    # Package Version Name
    try:
        cmd_and_pkg_ver = subprocess.check_output(
            ["grep", "-i", "versionName", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        version_name = re.search(r'versionName=".*?"', cmd_and_pkg_ver)
        if version_name:
            logger.info(f"   {version_name.group()}")
        else:
            logger.warning("    - android:versionName has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - android:versionName has not been observed.")

    # Minimum SDK Version
    try:
        cmd_and_pkg_minSdkVersion = subprocess.check_output(
            ["grep", "-i", "minSdkVersion", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        min_sdk_version = re.search(r'minSdkVersion=".*?"', cmd_and_pkg_minSdkVersion)
        if min_sdk_version:
            logger.info(f"   {min_sdk_version.group()}")
        else:
            logger.warning("    - android:minSdkVersion has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - android:minSdkVersion has not been observed.")

    # Target SDK Version
    try:
        cmd_and_pkg_targetSdkVersion = subprocess.check_output(
            ["grep", "-i", "targetSdkVersion", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        target_sdk_version = re.search(r'targetSdkVersion=".*?"', cmd_and_pkg_targetSdkVersion)
        if target_sdk_version:
            logger.info(f"   {target_sdk_version.group()}")
        else:
            logger.warning("    - android:targetSdkVersion has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - android:targetSdkVersion has not been observed.")

    # Network Security Config
    try:
        cmd_and_pkg_nwSecConf = subprocess.check_output(
            ["grep", "-i", "android:networkSecurityConfig=", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        nwSecConf_match = re.search(r'android:networkSecurityConfig="@xml/.*?"', cmd_and_pkg_nwSecConf)
        if nwSecConf_match:
            nwSecConf_split = nwSecConf_match.group().split('android:networkSecurityConfig="@xml/')
            nwSecConf_final = nwSecConf_split[1].strip('"').strip()
            logger.info(f"   {nwSecConf_final}")
        else:
            logger.warning("    - android:networkSecurityConfig attribute has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - android:networkSecurityConfig attribute has not been observed.")

    # Activities
    logger.info("\n==>> The Activities...\n")
    try:
        cmd_and_actv = subprocess.check_output(
            ["grep", "-ne", "<activity", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_actv)
    except subprocess.CalledProcessError:
        logger.warning("- No activities have been observed")

    # Exported Activities
    logger.info("[+] Looking for the Exported Activities specifically...\n\n")
    exp_actv_cmd = f"grep -ne '<activity' {and_manifest_path} | grep -e 'android:exported=\"true\"'"
    try:
        cmd_and_exp_actv = subprocess.check_output(
            ["bash", "-c", exp_actv_cmd],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_exp_actv)
        exported_count = cmd_and_exp_actv.count('android:exported="true"')
        logger.info(f"    > Total exported activities are: {exported_count}")
        logger.info("\n    > QuickNote: It is recommended to use exported activities securely, if observed.\n")
    except subprocess.CalledProcessError:
        logger.warning("\t- No exported activities have been observed.")



    # Package Name from AndroidManifest
    try:
        cmd_and_pkg_nm = subprocess.check_output(
            ["grep", "-i", "package", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        package_name = re.search(r'package=".*?"', cmd_and_pkg_nm)
        if package_name:
            logger.info(f"   {package_name.group()}")
        else:
            logger.warning("    - Package Name has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - Package Name has not been observed.")

    # Package Version Name
    try:
        cmd_and_pkg_ver = subprocess.check_output(
            ["grep", "-i", "versionName", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        version_name = re.search(r'versionName=".*?"', cmd_and_pkg_ver)
        if version_name:
            logger.info(f"   {version_name.group()}")
        else:
            logger.warning("    - android:versionName has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - android:versionName has not been observed.")

    # Minimum SDK Version
    try:
        cmd_and_pkg_minSdkVersion = subprocess.check_output(
            ["grep", "-i", "minSdkVersion", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        min_sdk_version = re.search(r'minSdkVersion=".*?"', cmd_and_pkg_minSdkVersion)
        if min_sdk_version:
            logger.info(f"   {min_sdk_version.group()}")
        else:
            logger.warning("    - android:minSdkVersion has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - android:minSdkVersion has not been observed.")

    # Target SDK Version
    try:
        cmd_and_pkg_targetSdkVersion = subprocess.check_output(
            ["grep", "-i", "targetSdkVersion", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        target_sdk_version = re.search(r'targetSdkVersion=".*?"', cmd_and_pkg_targetSdkVersion)
        if target_sdk_version:
            logger.info(f"   {target_sdk_version.group()}")
        else:
            logger.warning("    - android:targetSdkVersion has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - android:targetSdkVersion has not been observed.")

    # Network Security Config
    try:
        cmd_and_pkg_nwSecConf = subprocess.check_output(
            ["grep", "-i", "android:networkSecurityConfig=", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        nwSecConf_match = re.search(r'android:networkSecurityConfig="@xml/.*?"', cmd_and_pkg_nwSecConf)
        if nwSecConf_match:
            nwSecConf_split = nwSecConf_match.group().split('android:networkSecurityConfig="@xml/')
            nwSecConf_final = nwSecConf_split[1].strip('"').strip()
            logger.info(f"   {nwSecConf_final}")
        else:
            logger.warning("    - android:networkSecurityConfig attribute has not been observed.")
    except subprocess.CalledProcessError:
        logger.warning("    - android:networkSecurityConfig attribute has not been observed.")

    # Content Providers
    logger.info("\n==>> The Content Providers...\n")
    try:
        cmd_and_cont = subprocess.check_output(
            ["grep", "-ne", "<provider", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_cont)
    except subprocess.CalledProcessError:
        logger.warning("\t- No Content Providers have been observed.")

    # Exported Content Providers
    logger.info("[+] Looking for the Exported Content Providers specifically...\n\n")
    exp_cont_cmd = f"grep -ne '<provider' {and_manifest_path} | grep -e 'android:exported=\"true\"'"
    try:
        cmd_and_exp_cont = subprocess.check_output(
            ["bash", "-c", exp_cont_cmd],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_exp_cont)
        exported_count = cmd_and_exp_cont.count('android:exported="true"')
        logger.info(f"    > Total exported Content Providers are: {exported_count}")
    except subprocess.CalledProcessError:
        logger.warning("\t- No exported Content Providers have been observed.")

    # Broadcast Receivers
    logger.info("\n==>> The Broadcast Receivers...\n")
    try:
        cmd_and_brod = subprocess.check_output(
            ["grep", "-ne", "<receiver", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_brod)
    except subprocess.CalledProcessError:
        logger.warning("\t- No Broadcast Receivers have been observed.")

    # Exported Broadcast Receivers
    logger.info("[+] Looking for the Exported Broadcast Receivers specifically...\n\n")
    exp_brod_cmd = f"grep -ne '<receiver' {and_manifest_path} | grep -e 'android:exported=\"true\"'"
    try:
        cmd_and_exp_brod = subprocess.check_output(
            ["bash", "-c", exp_brod_cmd],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_exp_brod)
        exported_count = cmd_and_exp_brod.count('android:exported="true"')
        logger.info(f"    > Total exported Broadcast Receivers are: {exported_count}")
    except subprocess.CalledProcessError:
        logger.warning("\t- No exported Broadcast Receivers have been observed.")

    # Services
    logger.info("\n==>> The Services...\n")
    try:
        cmd_and_serv = subprocess.check_output(
            ["grep", "-ne", "<service", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_serv)
    except subprocess.CalledProcessError:
        logger.warning("\t- No Services have been observed.")

    # Exported Services
    logger.info("[+] Looking for the Exported Services specifically...\n\n")
    exp_serv_cmd = f"grep -ne '<service' {and_manifest_path} | grep -e 'android:exported=\"true\"'"
    try:
        cmd_and_exp_serv = subprocess.check_output(
            ["bash", "-c", exp_serv_cmd],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_exp_serv)
        exported_count = cmd_and_exp_serv.count('android:exported="true"')
        logger.info(f"    > Total exported Services are: {exported_count}")
    except subprocess.CalledProcessError:
        logger.warning("\t- No exported Services have been observed.")

    # Intent Filters
    logger.info("\n==>> The Intent Filters...\n")
    try:
        cmd_and_intentFilters = subprocess.check_output(
            ["grep", "-ne", "android.intent.", and_manifest_path],
            stderr=subprocess.STDOUT
        ).decode()
        logger.info(cmd_and_intentFilters)
    except subprocess.CalledProcessError:
        logger.warning("\t- No Intent Filters have been observed.")

    # APK Component Summary
    logger.info("\n==>> APK Component Summary")
    logger.info("[+] --------------------------------")
    logger.info(f"    Exported Activities: {exported_count}")
    logger.info(f"    Exported Content Providers: {exported_count}")
    logger.info(f"    Exported Broadcast Receivers: {exported_count}")
    logger.info(f"    Exported Services: {exported_count}")



    # SAST - Recursive file reading
    globpath = jadxpath + "sources/"
    globpath_res = jadxpath + "resources/"
    logger.info("\n")
    logger.info("[+] Let's start the static assessment based on 'OWASP MASVS'")
    logger.info("[+] ========================================================")

    # Read .java files - /sources folder
    files = []
    for root, dirs, files_in_dir in os.walk(globpath):
        for file in files_in_dir:
            files.append(os.path.join(root, file))

    # Read .xml files - /resources folder
    files_res = []
    for root, dirs, files_in_dir in os.walk(globpath_res):
        for file in files_in_dir:
            files_res.append(os.path.join(root, file))

    # OWASP MASVS - V2: Data Storage and Privacy Requirements
    logger.info("\n[+] Hunting begins based on 'V2: Data Storage and Privacy Requirements'")
    logger.info("[+] -------------------------------------------------------------------")

    # MASVS V2 - MSTG-STORAGE-2 - Shared Preferences
    logger.info("\n==>> The Shared Preferences related instances...")
    countSharedPref = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_getSharedPreferences = subprocess.check_output(
                    ["grep", "-nr", "-F", "getSharedPreferences(", sources_file],
                    stderr=subprocess.STDOUT
                )
                cmd_and_pkg_getSharedPreferences_output = cmd_and_pkg_getSharedPreferences.decode("utf-8")
                if "getSharedPreferences" in cmd_and_pkg_getSharedPreferences_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_getSharedPreferences_output)
                    countSharedPref += 1
            except subprocess.CalledProcessError:
                pass

    if countSharedPref > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to use shared preferences appropriately, if observed. "
                    "Please note that, Misuse of the SharedPreferences API can often lead to the exposure of sensitive data. "
                    "MODE_WORLD_READABLE allows all applications to access and read the file contents. Applications compiled with "
                    "an android:targetSdkVersion value less than 17 may be affected, if they run on an OS version that was released "
                    "before Android 4.2 (API level 17).")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-2 - SQLite Database 
    logger.info("\n==>>  The SQLite Database Storage related instances...")
    countSqliteDb = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_sqlitedatbase = subprocess.check_output(
                    ["grep", "-nr", "-e", "openOrCreateDatabase", "-e", "getWritableDatabase", "-e", "getReadableDatabase", sources_file],
                    stderr=subprocess.STDOUT
                )
                cmd_and_pkg_sqlitedatbase_output = cmd_and_pkg_sqlitedatbase.decode("utf-8")
                if ("openOrCreateDatabase" in cmd_and_pkg_sqlitedatbase_output or
                    "getWritableDatabase" in cmd_and_pkg_sqlitedatbase_output or
                    "getReadableDatabase" in cmd_and_pkg_sqlitedatbase_output):
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_sqlitedatbase_output)
                    countSqliteDb += 1
            except subprocess.CalledProcessError:
                pass

    if countSqliteDb > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that sensitive data should not be stored in unencrypted SQLite databases, if observed. "
                    "Please note that, SQLite databases should be password-encrypted.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-2 - Firebase Database 
    logger.info("\n==>> The Firebase Database instances...")
    countFireDB = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            try:
                cmd_and_pkg_firebase = subprocess.check_output(
                    ["grep", "-nr", "-F", ".firebaseio.com", sources_file],
                    stderr=subprocess.STDOUT
                )
                cmd_and_pkg_firebase_output = cmd_and_pkg_firebase.decode("utf-8")
                if "firebaseio" in cmd_and_pkg_firebase_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_firebase_output)
                    countFireDB += 1
            except subprocess.CalledProcessError:
                pass

    if countFireDB > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that Firebase Realtime database instances should not be misconfigured, if observed. "
                    "Please note that, An attacker can read the content of the database without any authentication, if rules are set "
                    "to allow open access or access is not restricted to specific users for specific data sets.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-2 - Realm Database 
    logger.info("\n==>> The Realm Database instances...")
    countRealmDB = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_realm = subprocess.check_output(
                    ["grep", "-nr", "-e", "RealmConfiguration", sources_file],
                    stderr=subprocess.STDOUT
                )
                cmd_and_pkg_realm_output = cmd_and_pkg_realm.decode("utf-8")
                if "RealmConfiguration" in cmd_and_pkg_realm_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_realm_output)
                    countRealmDB += 1
            except subprocess.CalledProcessError:
                pass

    if countRealmDB > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that Realm database instances should not be misconfigured, if observed. "
                    "Please note that, the database and its contents have been encrypted with a key stored in the configuration file.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # Internal Storage
    logger.info("\n==>> The Internal Storage related instances...\n")
    countIntStorage = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_internalStorage = subprocess.run(
                ["grep", "-nr", "-e", "openFileOutput", "-e", "MODE_WORLD_READABLE", "-e", "MODE_WORLD_WRITEABLE", "-e", "FileInputStream", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_internalStorage_output = cmd_and_pkg_internalStorage.stdout
            if "MODE_WORLD_READABLE" in cmd_and_pkg_internalStorage_output or "MODE_WORLD_WRITEABLE" in cmd_and_pkg_internalStorage_output:
                logger.info(sources_file)
                if "openFileOutput" in cmd_and_pkg_internalStorage_output or "FileInputStream" in cmd_and_pkg_internalStorage_output or "MODE_WORLD_READABLE" in cmd_and_pkg_internalStorage_output or "MODE_WORLD_WRITEABLE" in cmd_and_pkg_internalStorage_output:
                    logger.info(cmd_and_pkg_internalStorage_output)
                    countIntStorage += 1

    if countIntStorage > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that sensitive files saved to the internal storage should not be accessed by other applications, if observed. Modes such as MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE may pose a security risk.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # External Storage
    logger.info("\n==>> The External Storage related instances...\n")
    countExtStorage = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_externalStorage = subprocess.run(
                ["grep", "-nr", "-e", "getExternalFilesDir", "-e", "getExternalFilesDirs", "-e", "getExternalCacheDir", "-e", "getExternalCacheDirs", "-e", "getCacheDir", "-e", "getExternalStorageState", "-e", "getExternalStorageDirectory", "-e", "getExternalStoragePublicDirectory", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_externalStorage_output = cmd_and_pkg_externalStorage.stdout
            if any(x in cmd_and_pkg_externalStorage_output for x in ["getExternalFilesDirs(", "getExternalCacheDir(", "getExternalFilesDirs(", "getCacheDir(", "getExternalStorageState(", "getExternalStorageDirectory(", "getExternalStoragePublicDirectory("]):
                logger.info(sources_file)
                logger.info(cmd_and_pkg_externalStorage_output)
                countExtStorage += 1

    if countExtStorage > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that any sensitive data should not be stored in the external storage, if observed. Files saved to external storage are world-readable and may be accessed by unauthorized parties.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # Temporary File Creation
    logger.info("\n==>> The Temporary File Creation instances...\n")
    countTempFile = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_tempFile = subprocess.run(
                ["grep", "-nr", "-F", ".createTempFile(", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_tempFile_output = cmd_and_pkg_tempFile.stdout
            if ".createTempFile(" in cmd_and_pkg_tempFile_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_tempFile_output)
                countTempFile += 1

    if countTempFile > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that the temporary files should be securely deleted upon their usage, if observed. Insecure temporary files can leave application and system data vulnerable to attack.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-277: Insecure Inherited Permissions")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # Local Storage - Input Validation
    logger.info("\n==>> The Local Storage - Input Validation...\n")
    countSharedPrefEd = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_sharedPreferencesEditor = subprocess.run(
                ["grep", "-nr", "-F", "SharedPreferences.Editor", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_sharedPreferencesEditor_output = cmd_and_pkg_sharedPreferencesEditor.stdout
            if "SharedPreferences.Editor" in cmd_and_pkg_sharedPreferencesEditor_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_sharedPreferencesEditor_output)
                countSharedPrefEd += 1

    if countSharedPrefEd > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that input validation needs to be applied on sensitive data when it is read back again. Any process can override the data for publicly accessible data storage.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-922: Insecure Storage of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # Information Leaks via Logs
    logger.info("\n==>> The Information Leaks via Logs...\n")
    countLogs = 0
    countLogs2 = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_logs = subprocess.run(
                ["grep", "-nr", "-e", "Log.v(", "-e", "Log.d(", "-e", "Log.i(", "-e", "Log.w(", "-e", "Log.e(", "-e", "logger.log(", "-e", "logger.logp(", "-e", "log.info", "-e", "System.out.print", "-e", "System.err.print", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_logs_output = cmd_and_pkg_logs.stdout
            if any(x in cmd_and_pkg_logs_output for x in ["Log.v(", "Log.d(", "Log.i(", "Log.w(", "Log.e(", "logger.log(", "logger.logp(", "log.info", "System.out.print", "System.err.print"]):
                logger.info(sources_file)
                logger.info(cmd_and_pkg_logs_output)
                countLogs += 1
                countLogs2 += cmd_and_pkg_logs_output.count("\n")

    if countLogs > 0:
        logger.info(f"[+] Total file sources are: {countLogs} & its total instances are: {countLogs2}")
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that any sensitive data should not be part of the log's output or revealed in Stacktraces.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-3 | CWE-532: Insertion of Sensitive Information into Log File")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")


    colorPurple = "\033[35m"
    colorReset = "\033[0m"
    colorBrown = "\033[33m"
    colorCyan = "\033[36m"
    colorBlueBold = "\033[1;34m"



    # MASVS V2 - MSTG-STORAGE-4 - NotificationManager
    print(colorPurple)
    logger.info("\n==>> The Push Notification instances...\n")
    print(colorReset)

    countNotiManag = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                result = subprocess.run(["grep", "-nr", "-e", "NotificationManager", "-e", r"\.setContentTitle(", "-e", r"\.setContentText(", sources_file],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                cmd_and_pkg_notificationManager_output = result.stdout.decode("utf-8")

                if "setContentTitle" in cmd_and_pkg_notificationManager_output or "setContentText" in cmd_and_pkg_notificationManager_output:
                    print(colorBrown)
                    logger.info(sources_file)
                    print(colorReset)

                    if "NotificationManager" in cmd_and_pkg_notificationManager_output or "setContentTitle" in cmd_and_pkg_notificationManager_output or "setContentText" in cmd_and_pkg_notificationManager_output:
                        logger.info(cmd_and_pkg_notificationManager_output)
                        countNotiManag += 1
            except subprocess.CalledProcessError:
                pass

    if countNotiManag > 0:
        print(colorCyan)
        logger.info("[!] QuickNote:")
        print(colorReset)
        logger.info("    - It is recommended that any sensitive data should not be notified via the push notifications, if observed. Please note that, It would be necessary to understand how the application is generating the notifications and which data ends up being shown.")
        print(colorCyan)
        logger.info("\n[*] Reference:")
        print(colorReset)
        logger.info("    - OWASP MASVS: MSTG-STORAGE-4 | CWE-829: Inclusion of Functionality from Untrusted Control Sphere")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-5 - Keyboard Cache
    print(colorPurple)
    logger.info("\n==>> The Keyboard Cache instances...\n")
    print(colorReset)

    countKeyCache = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            try:
                result = subprocess.run(["grep", "-nr", "-e", ":inputType=", sources_file],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                cmd_and_pkg_keyboardCache_output = result.stdout.decode("utf-8")

                if "textAutoComplete" in cmd_and_pkg_keyboardCache_output or "textAutoCorrect" in cmd_and_pkg_keyboardCache_output:
                    print(colorBrown)
                    logger.info(sources_file)
                    print(colorReset)
                    logger.info(cmd_and_pkg_keyboardCache_output)
                    countKeyCache += 1
            except subprocess.CalledProcessError:
                pass

    if countKeyCache > 0:
        print(colorCyan)
        logger.info("[!] QuickNote:")
        print(colorReset)
        logger.info("    - It is recommended to set the android input type as textNoSuggestions for any sensitive data, if observed.")
        print(colorCyan)
        logger.info("\n[*] Reference:")
        print(colorReset)
        logger.info("    - OWASP MASVS: MSTG-STORAGE-5 | CWE-524: Use of Cache Containing Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-7 - Sensitive Data Disclosure Through the User Interface
    print(colorPurple)
    logger.info("\n==>>  The Sensitive Data Disclosure through the User Interface...\n")
    print(colorReset)

    countInputType = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            try:
                result = subprocess.run(["grep", "-nri", "-e", ':inputType="textPassword"', sources_file],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                cmd_and_pkg_inputType_output = result.stdout.decode("utf-8")

                if ":inputType=" in cmd_and_pkg_inputType_output:
                    print(colorBrown)
                    logger.info(sources_file)
                    print(colorReset)
                    logger.info(cmd_and_pkg_inputType_output)
                    countInputType += 1
            except subprocess.CalledProcessError:
                pass

    if countInputType == 0:
        print(colorCyan)
        logger.info("[!] QuickNote:")
        print(colorReset)
        logger.info('    - It is recommended not to disclose any sensitive data such as password, card details, etc. in the clear-text format via User Interface. Make sure that the application is masking sensitive user input by using the inputType="textPassword" attribute. It is useful to mitigate risks such as shoulder surfing.')
        print(colorCyan)
        logger.info("\n[*] Reference:")
        print(colorReset)
        logger.info("    - OWASP MASVS: MSTG-STORAGE-7 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    if countInputType > 0:
        print(colorCyan)
        logger.info("[!] QuickNote:")
        print(colorReset)
        logger.info('    - It seems that the application has implemented inputType="textPassword" attribute to hide the certain information, if observed. Make sure that the application is not disclosing any sensitive data such as password, card details, etc. in the clear-text format via User Interface.')
        print(colorCyan)
        logger.info("\n[*] Reference:")
        print(colorReset)
        logger.info("    - OWASP MASVS: MSTG-STORAGE-7 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor")

    # MASVS V2 - MSTG-STORAGE-9 - Auto-Generated Screenshots
    logger.info("\n==>> The Auto-Generated Screenshots protection...\n")
    countScreenShots = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_screenShots = subprocess.check_output(
                    ["grep", "-nr", "-e", "FLAG_SECURE", sources_file], stderr=subprocess.STDOUT
                ).decode()
                if "FLAG_SECURE" in cmd_and_pkg_screenShots:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_screenShots)
                    countScreenShots += 1
            except subprocess.CalledProcessError:
                pass

    if countScreenShots >= 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to set the FLAG_SECURE option to protect from Auto-Generated Screenshots issue.")
        logger.info("[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-9 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-10 - Memory flush
    logger.info("\n==>> The flush instances utilized for clearing the Memory...\n")
    countFlushMem = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_flushMem = subprocess.check_output(
                    ["grep", "-nr", "-F", ".flush(", sources_file], stderr=subprocess.STDOUT
                ).decode()
                if ".flush(" in cmd_and_pkg_flushMem:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_flushMem)
                    countFlushMem += 1
            except subprocess.CalledProcessError:
                pass

    if countFlushMem > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that the sensitive data should be flushed appropriately after its usage.")
        logger.info("[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-10 | CWE-316: Cleartext Storage of Sensitive Information in Memory")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-10 - ClipboardManager
    logger.info("\n==>> The Clipboard Copying instances...\n")
    countClipCopy = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_clipCopy = subprocess.check_output(
                    ["grep", "-nr", "-e", "ClipboardManager", "-e", ".setPrimaryClip(", "-e", "OnPrimaryClipChangedListener", sources_file],
                    stderr=subprocess.STDOUT
                ).decode()
                if "setPrimaryClip" in cmd_and_pkg_clipCopy or "OnPrimaryClipChangedListener" in cmd_and_pkg_clipCopy:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_clipCopy)
                    countClipCopy += 1
            except subprocess.CalledProcessError:
                pass

    if countClipCopy > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that any sensitive data should not be copied to the clipboard.")
        logger.info("[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-10 | CWE-316: Cleartext Storage of Sensitive Information in Memory")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2/data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-14 - Hard-coded Information
    logger.info("\n==>> The possible Hard-coded Information...\n")
    countHardInfo = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_hardcodeInfo = subprocess.check_output(
                    ["grep", "-nri", "-E", r'String (password|key|token|username|url|database|secret|bearer) = "', sources_file],
                    stderr=subprocess.STDOUT
                ).decode()
                if any(keyword in cmd_and_pkg_hardcodeInfo for keyword in ["password", "key", "token", "username", "url", "database", "secret", "bearer"]):
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_hardcodeInfo)
                    countHardInfo += 1

                cmd_and_pkg_hardcodeEmail = subprocess.check_output(
                    ["grep", "-nr", "-E", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b", sources_file],
                    stderr=subprocess.STDOUT
                ).decode()
                if "@" in cmd_and_pkg_hardcodeEmail:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_hardcodeEmail)
                    countHardInfo += 1

                cmd_and_pkg_hardcodePrivIP = subprocess.check_output(
                    ["grep", "-nr", "-E", r"(192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))", sources_file],
                    stderr=subprocess.STDOUT
                ).decode()
                if any(ip in cmd_and_pkg_hardcodePrivIP for ip in ["192", "172", "10"]):
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_hardcodePrivIP)
                    countHardInfo += 1

                cmd_and_pkg_cloudURLs = subprocess.check_output(
                    ["grep", "-nr", "-E", r"(\.amazonaws.com|\.(file|blob).core.windows.net|\.(storage|firebasestorage).googleapis.com)", sources_file],
                    stderr=subprocess.STDOUT
                ).decode()
                if any(url in cmd_and_pkg_cloudURLs for url in ["amazonaws.com", "core.windows.net", "googleapis.com"]):
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_cloudURLs)
                    countHardInfo += 1

                cmd_and_pkg_begin = subprocess.check_output(
                    ["grep", "-nr", "-e", "-BEGIN ", sources_file],
                    stderr=subprocess.STDOUT
                ).decode()
                if "BEGIN" in cmd_and_pkg_begin:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_begin)
                    countHardInfo += 1

            except subprocess.CalledProcessError:
                pass

    if countHardInfo > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that the hard-coded sensitive data (such as Private IPs/E-mails, User/DB details, etc.) should not be stored unless secured specifically.")
        logger.info("[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-14 | CWE-312: Cleartext Storage of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2/data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-14 - Possible Hard-coded Keys/Tokens/Secrets
    logger.info("\n==>> The potential Hard-coded Keys/Tokens/Secrets...\n")
    countHardcodedKeys = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            try:
                cmd_and_pkg_hardcodedKeys = subprocess.check_output(
                    ["grep", "-nri", "-E", r'(_key"|_secret"|_token"|_client_id"|_api"|_debug"|_prod"|_stage")', "--include", "strings.xml", sources_file],
                    stderr=subprocess.STDOUT
                ).decode()
                if any(keyword in cmd_and_pkg_hardcodedKeys for keyword in ["_key", "_secret", "_token", "_client_id", "_api", "_debug", "_prod", "_stage"]):
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_hardcodedKeys)
                    countHardcodedKeys += 1
            except subprocess.CalledProcessError:
                pass

    if countHardcodedKeys > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that the hard-coded keys/tokens/secrets should not be stored unless secured specifically.")
        logger.info("[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-STORAGE-14 | CWE-312: Cleartext Storage of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2/data_storage_and_privacy_requirements")


    logger.info("\n")
    logger.info(f"{colorBlueBold}[+] Hunting begins based on \"V5: Network Communication Requirements\"{colorReset}")
    logger.info("[+] ----------------------------------------------------------------")

    # Network Security Configuration file check
    logger.info(f"{colorPurple}\n==>> The presence of the Network Security Configuration file...{colorReset}")
    if nwSecConf_final == "`":
        net_sec_conf_file = "res/xml/network_security_config.xml"
    else:
        net_sec_conf_file_temp = "res/xml/"
        net_sec_conf_file = net_sec_conf_file_temp + nwSecConf_final + ".xml"

    try:
        os.stat(net_sec_conf_file)
    except FileNotFoundError:
        logger.info(f"{colorCyan}\n[!] QuickNote:{colorReset}")
        logger.info("    - It is recommended to configure the Network Security Configuration file (such as network_security_config.xml) as it does not exist. "
                    "Please note that, Network Security Config file can be used to protect against cleartext traffic, set up trusted certificate authorities, "
                    "implement certificate pinning, etc. in terms of network security settings.")
        logger.info(f"{colorCyan}\n[*] Reference:{colorReset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
    else:
        logger.info(f"{colorCyan}\n[+] QuickNote:{colorReset}")
        logger.info(f"    - It has been observed that Network Security Configuration file is present at:\n      {net_sec_conf_file}")
        logger.info(f"{colorCyan}\n[*] Reference:{colorReset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # Possible MITM attack check
    logger.info(f"{colorPurple}\n==>> The Possible MITM attack...\n{colorReset}")
    countHTTP = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_unencryptedProtocol = subprocess.run(["grep", "-nri", "-e", "(HttpURLConnection)", "-e", "SSLCertificateSocketFactory.getInsecure(", sources_file],
                                                            capture_output=True, text=True)
            cmd_and_pkg_unencryptedProtocol_output = cmd_and_pkg_unencryptedProtocol.stdout
            if "HttpURLConnection" in cmd_and_pkg_unencryptedProtocol_output or "getInsecure" in cmd_and_pkg_unencryptedProtocol_output:
                logger.info(f"{colorBrown}{sources_file}{colorReset}")
                logger.info(cmd_and_pkg_unencryptedProtocol_output)
                countHTTP += 1

    if countHTTP > 0:
        logger.info(f"{colorCyan}\n[!] QuickNote:{colorReset}")
        logger.info("    - It is recommended not to use any unencrypted transmission mechanisms for sensitive data. "
                    "Please note that, the HTTP protocol does not provide any encryption of the transmitted data, which can be easily intercepted by an attacker.")
        logger.info(f"{colorCyan}\n[*] Reference:{colorReset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-319: Cleartext Transmission of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # Weak SSL/TLS protocols check
    logger.info(f"{colorPurple}\n==>> The Weak SSL/TLS protocols...\n{colorReset}")
    countWeakTLS = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_weakTLSProtocol = subprocess.run(["grep", "-nri", "-e", "SSLContext.getInstance(", "-e", "tlsVersions(TlsVersion", sources_file],
                                                        capture_output=True, text=True)
            cmd_and_pkg_weakTLSProtocol_output = cmd_and_pkg_weakTLSProtocol.stdout
            if "tls" in cmd_and_pkg_weakTLSProtocol_output or "SSL" in cmd_and_pkg_weakTLSProtocol_output:
                logger.info(f"{colorBrown}{sources_file}{colorReset}")
                logger.info(cmd_and_pkg_weakTLSProtocol_output)
                countWeakTLS += 1

    if countWeakTLS > 0:
        logger.info(f"{colorCyan}\n[!] QuickNote:{colorReset}")
        logger.info("    - It is recommended to enforce TLS 1.2 as the minimum protocol version. "
                    "Please note that, Failure to do so could open the door to downgrade attacks such as DROWN/POODLE/BEAST etc.")
        logger.info(f"{colorCyan}\n[*] Reference:{colorReset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-2 | CWE-326: Inadequate Encryption Strength")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # Cleartext Traffic check
    logger.info(f"{colorPurple}\n==>>  The app is allowing cleartext traffic...\n{colorReset}")
    countClearTraffic = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            cmd_and_pkg_cleartextTraffic = subprocess.run(["grep", "-nr", "-e", "android:usesCleartextTraffic", "-e", "cleartextTrafficPermitted", sources_file],
                                                        capture_output=True, text=True)
            cmd_and_pkg_cleartextTraffic_output = cmd_and_pkg_cleartextTraffic.stdout
            if "android:usesCleartextTraffic" in cmd_and_pkg_cleartextTraffic_output or "cleartextTrafficPermitted" in cmd_and_pkg_cleartextTraffic_output:
                logger.info(f"{colorBrown}{sources_file}{colorReset}")
                logger.info(cmd_and_pkg_cleartextTraffic_output)
                countClearTraffic += 1

    if countClearTraffic > 0:
        logger.info(f"{colorCyan}\n[!] QuickNote:{colorReset}")
        logger.info("    - It is recommended to set android:usesCleartextTraffic or cleartextTrafficPermitted to false. "
                    "Please note that, Sensitive information should be sent over secure channels only.")
        logger.info(f"{colorCyan}\n[*] Reference:{colorReset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-2 | CWE-319: Cleartext Transmission of Sensitive Information")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")


    # MASVS V5 - MSTG-NETWORK-3 - Server Certificate
    logger.info("\n==>> The Server Certificate verification...\n")
    count_server_cert = 0
    for sources_file in files:
        if pathlib.Path(sources_file).suffix == ".java":
            cmd_server_cert = subprocess.run(
                ["grep", "-nri", "-e", "X509Certificate", "-e", "checkServerTrusted(", "-e", "checkClientTrusted(", "-e", "getAcceptedIssuers(", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_server_cert_output = cmd_server_cert.stdout.decode('utf-8')
            if "checkServerTrusted" in cmd_server_cert_output or "checkClientTrusted" in cmd_server_cert_output or "getAcceptedIssuers" in cmd_server_cert_output:
                logger.info(sources_file)
                logger.info(cmd_server_cert_output)
                count_server_cert += 1

    if count_server_cert > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to appropriately verify the Server Certificate, if observed. Please note that, It should be signed by a trusted CA, not expired, not self-signed, etc. While implementing a custom X509TrustManager, the certificate chain needs to be verified appropriately, else the possibility of MITM attacks increases by providing an arbitrary certificate by an attacker.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-3 | CWE-295: Improper Certificate Validation")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # MASVS V5 - MSTG-NETWORK-3 - WebView Server Certificate
    logger.info("\n==>> The WebView Server Certificate verification...\n")
    count_webview_cert = 0
    for sources_file in files:
        if pathlib.Path(sources_file).suffix == ".java":
            cmd_webview_cert = subprocess.run(
                ["grep", "-nri", "-e", "onReceivedSslError", "-e", "sslErrorHandler", "-e", ".proceed(", "-e", "setWebViewClient", "-e", "findViewById", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_webview_cert_output = cmd_webview_cert.stdout.decode('utf-8')
            if "onReceivedSslError" in cmd_webview_cert_output:
                logger.info(sources_file)
                logger.info(cmd_webview_cert_output)
                count_webview_cert += 1

    if count_webview_cert > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - The application seems to be implementing its own onReceivedSslError method, if observed. Please note that, the application should appropriately verify the WebView Server Certificate implementation (such as having a call to the handler.cancel method). TLS certificate errors should not be ignored as the mobile browser performs the server certificate validation when a WebView is used.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-3 | CWE-295: Improper Certificate Validation")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # MASVS V5 - MSTG-NETWORK-3 - Hostname Verification
    logger.info("\n==>> The Hostname Verification...\n")
    count_host_verf = 0
    for sources_file in files:
        if pathlib.Path(sources_file).suffix == ".java":
            cmd_hostname_verifier = subprocess.run(
                ["grep", "-nri", "-e", " HostnameVerifier", "-e", ".setHostnameVerifier(", "-e", ".setDefaultHostnameVerifier(", "-e", "NullHostnameVerifier", "-e", "ALLOW_ALL_HOSTNAME_VERIFIER", "-e", "AllowAllHostnameVerifier", "-e", "NO_VERIFY", "-e", " verify(String ", "-e", "return true", "-e", "return 1", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_hostname_verifier_output = cmd_hostname_verifier.stdout.decode('utf-8')
            if "setHostnameVerifier(" in cmd_hostname_verifier_output or "setDefaultHostnameVerifier(" in cmd_hostname_verifier_output or "NullHostnameVerifier" in cmd_hostname_verifier_output or "ALLOW_ALL_HOSTNAME_VERIFIER" in cmd_hostname_verifier_output or "AllowAllHostnameVerifier" in cmd_hostname_verifier_output or "NO_VERIFY" in cmd_hostname_verifier_output or "verify(String" in cmd_hostname_verifier_output:
                logger.info(sources_file)
                logger.info(cmd_hostname_verifier_output)
                count_host_verf += 1

    if count_host_verf > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended not to set ALLOW_ALL_HOSTNAME_VERIFIER or NO_VERIFY, if observed. Please note that, If class always returns true; upon verify() method, the possibility of MITM attacks increases. The application should always verify a hostname before setting up a trusted connection.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-3 | CWE-297: Improper Validation of Certificate with Host Mismatch")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # MASVS V5 - MSTG-NETWORK-4 - Hard-coded Certificates/Key/Keystore files
    logger.info("\n==>> The Hard-coded Certificates/Key/Keystore files...\n")
    count_cert = 0
    for sources_file in files_res:
        if pathlib.Path(sources_file).suffix in [".cer", ".pem", ".cert", ".crt", ".pub", ".key", ".pfx", ".p12", ".der", ".jks", ".bks"]:
            logger.info(sources_file)
            count_cert += 1
    if count_cert > 0:
        logger.info(f"{colorCyan}[!] QuickNote:{color_reset}")
        logger.info("    - Hard-coded Certificates/Key/Keystore files have been identified, if observed. Please note that, Attacker may bypass SSL Pinning by adding their proxy's certificate to the trusted keystore with the tool such as keytool.")
        logger.info(f"{colorCyan}\n[*] Reference:{color_reset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # MASVS V5 - MSTG-NETWORK-4 - Certificate Pinning settings
    logger.info(f"{colorPurple}\n==>> The Certificate Pinning settings...\n{color_reset}")
    count_cert_pinning = 0
    for sources_file in files_res:
        if sources_file.endswith('.xml'):
            result = subprocess.run(['grep', '-nr', '-e', '<pin-set', '-e', '<pin digest', '-e', '<domain', '-e', '<base', sources_file],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                cmd_and_pkg_cert_pinning_output = result.stdout.decode()
                if "<pin" in cmd_and_pkg_cert_pinning_output:
                    logger.info(f"{colorBrown}{sources_file}{color_reset}")
                if any(tag in cmd_and_pkg_cert_pinning_output for tag in ["<pin", "<domain", "<base"]):
                    logger.info(cmd_and_pkg_cert_pinning_output)
                    count_cert_pinning += 1

    if count_cert_pinning > 0:
        logger.info(f"{colorCyan}[!] QuickNote:{color_reset}")
        logger.info("    - It is recommended to appropriately set the certificate pinning in the Network Security Configuration file, if observed. Please note that, The expiration time and backup pins should be set.")
        logger.info(f"{color_cyan}\n[*] Reference:{color_reset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # MASVS V5 - MSTG-NETWORK-4 - Certificate Pinning implementation
    logger.info(f"{colorPurple}\n==>> The Certificate Pinning implementation...\n{color_reset}")
    count_cert_keystore = 0
    for sources_file in files:
        if sources_file.endswith('.java'):
            result = subprocess.run(['grep', '-nr', '-e', 'certificatePinner', '-e', 'KeyStore.getInstance', '-e', 'trustManagerFactory', '-e', 'Retrofit.Builder(', '-e', 'Picasso.Builder(', sources_file],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                cmd_and_pkg_cert_keystore_output = result.stdout.decode()
                if any(tag in cmd_and_pkg_cert_keystore_output for tag in ["certificatePinner", "KeyStore.getInstance", "trustManagerFactory", "Builder("]):
                    logger.info(f"{colorBrown}{sources_file}{color_reset}")
                    logger.info(cmd_and_pkg_cert_keystore_output)
                    count_cert_keystore += 1

    if count_cert_keystore > 0:
        logger.info(f"{colorCyan}[!] QuickNote:{color_reset}")
        logger.info("    - It is recommended to implement Certificate Pinning appropriately, if observed. Please note that the application should use its own certificate store, or pins the endpoint certificate or public key. Further, it should not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA.")
        logger.info(f"{colorCyan}\n[*] Reference:{color_reset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # MASVS V5 - MSTG-NETWORK-4 - Custom Trust Anchors
    logger.info(f"{colorPurple}\n==>> The custom Trust Anchors...\n{color_reset}")
    count_trust_anchors = 0
    for sources_file in files_res:
        if sources_file.endswith('.xml'):
            result = subprocess.run(['grep', '-nr', '-e', '<certificates src=', '-e', '<domain', '-e', '<base', sources_file],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                cmd_and_pkg_trust_anchors_output = result.stdout.decode()
                if "<certificates" in cmd_and_pkg_trust_anchors_output:
                    logger.info(f"{colorBrown}{sources_file}{color_reset}")
                if any(tag in cmd_and_pkg_trust_anchors_output for tag in ["<certificates", "<domain", "<base"]):
                    logger.info(cmd_and_pkg_trust_anchors_output)
                    count_trust_anchors += 1

    if count_trust_anchors > 0:
        logger.info(f"{colorCyan}[!] QuickNote:{color_reset}")
        logger.info("    - It is recommended that custom Trust Anchors such as <certificates src=user should be avoided, if observed. The <pin> should be set appropriately if it cannot be avoided. Please note that, If the app will trust user-supplied CAs by using a custom Network Security Configuration with a custom trust anchor, the possibility of MITM attacks increases.")
        logger.info(f"{colorCyan}\n[*] Reference:{color_reset}")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-4 | CWE-295: Improper Certificate Validation")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    # MASVS V5 - MSTG-NETWORK-6 - Security Provider
    logger.info("\n==>> The Security Provider implementation...\n")
    countProInst = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_ProviderInstaller = subprocess.run(
                ["grep", "-nr", "-e", " ProviderInstaller.installIfNeeded", "-e", " ProviderInstaller.installIfNeededAsync", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_ProviderInstaller_output = cmd_and_pkg_ProviderInstaller.stdout
            if "ProviderInstaller" in cmd_and_pkg_ProviderInstaller_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_ProviderInstaller_output)
                countProInst += 1

    if countProInst == 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that applications based on the Android SDK should depend on GooglePlayServices, if not observed. Please note that, The ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync to prevent SSL exploits.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-6 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")

    if countProInst > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It seems that the ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync to prevent SSL exploits as Android relies on a security provider which comes with the device, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-NETWORK-6 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")


    # OWASP MASVS - V6: Platform Interaction Requirements
    logger.info("\n")
    logger.info('[+] Hunting begins based on "V6: Platform Interaction Requirements"')
    logger.info("[+] ---------------------------------------------------------------")

    # MASVS V6 - MSTG-PLATFORM-1 - Permissions
    logger.info("\n==>> The Permissions...\n")
    countPerm = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            cmd_and_pkg_permission = subprocess.run(
                ["grep", "-nr", "-E", "<uses-permission|<permission", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_permission_output = cmd_and_pkg_permission.stdout
            if "permission" in cmd_and_pkg_permission_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_permission_output)
                countPerm += 1

    if countPerm > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that the appropriate protectionLevel should be configured in the Permission declaration, if observed. Please note that, Dangerous permissions involve the user’s privacy.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-1 - Deprecated/Unsupprotive Permissions
    logger.info("\n==>> The Deprecated/Unsupprotive Permissions...\n")
    countDeprecatedPerm = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            cmd_and_pkg_deprecatedPerm = subprocess.run(
                ["grep", "-nr", "-E", "BIND_CARRIER_MESSAGING_SERVICE|BIND_CHOOSER_TARGET_SERVICE|GET_TASKS|PERSISTENT_ACTIVITY|PROCESS_OUTGOING_CALLS|READ_INPUT_STATE|RESTART_PACKAGES|SET_PREFERRED_APPLICATIONS|SMS_FINANCIAL_TRANSACTIONS|USE_FINGERPRINT|UNINSTALL_SHORTCUT", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_deprecatedPerm_output = cmd_and_pkg_deprecatedPerm.stdout
            if any(perm in cmd_and_pkg_deprecatedPerm_output for perm in ["BIND_", "GET_TASKS", "PERSISTENT_ACTIVITY", "PROCESS_OUTGOING_CALLS", "READ_INPUT_STATE", "RESTART_PACKAGES", "SET_PREFERRED_APPLICATIONS", "SMS_FINANCIAL_TRANSACTIONS", "USE_FINGERPRINT", "UNINSTALL_SHORTCUT"]):
                logger.info(sources_file)
                logger.info(cmd_and_pkg_deprecatedPerm_output)
                countDeprecatedPerm += 1

    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_deprecatedPerm = subprocess.run(
                ["grep", "-nr", "-E", "BIND_CARRIER_MESSAGING_SERVICE|BIND_CHOOSER_TARGET_SERVICE|GET_TASKS|PERSISTENT_ACTIVITY|PROCESS_OUTGOING_CALLS|READ_INPUT_STATE|RESTART_PACKAGES|SET_PREFERRED_APPLICATIONS|SMS_FINANCIAL_TRANSACTIONS|USE_FINGERPRINT|UNINSTALL_SHORTCUT", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_deprecatedPerm_output = cmd_and_pkg_deprecatedPerm.stdout
            if any(perm in cmd_and_pkg_deprecatedPerm_output for perm in ["BIND_", "GET_TASKS", "PERSISTENT_ACTIVITY", "PROCESS_OUTGOING_CALLS", "READ_INPUT_STATE", "RESTART_PACKAGES", "SET_PREFERRED_APPLICATIONS", "SMS_FINANCIAL_TRANSACTIONS", "USE_FINGERPRINT", "UNINSTALL_SHORTCUT"]):
                logger.info(sources_file)
                logger.info(cmd_and_pkg_deprecatedPerm_output)
                countDeprecatedPerm += 1

    if countDeprecatedPerm > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that the application should not use the Deprecated or Unsupportive permissions, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

            
    # MASVS V6 - MSTG-PLATFORM-1 - Custom Permissions
    logger.info("\n==>> The Custom Permissions...\n")
    countCustPerm = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_custPerm = subprocess.run(
                ["grep", "-nr", "-e", "checkCallingOrSelfPermission", "-e", "checkSelfPermission", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_custPerm_output = cmd_and_pkg_custPerm.stdout
            if "checkCallingOrSelfPermission" in cmd_and_pkg_custPerm_output or "checkSelfPermission" in cmd_and_pkg_custPerm_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_custPerm_output)
                countCustPerm += 1

    if countCustPerm > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that Custom Permissions should be used appropriately, if observed. Please note that, The permissions provided programmatically are enforced in the manifest file, as those are more error-prone and can be bypassed more easily with, e.g., runtime instrumentation.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-1 - Exported service/activity/provider/receiver without permission set
    logger.info("\n==>> The Exported service/activity/provider/receiver without permission set...\n")
    exp_PermNotSet1 = 'grep -nE "<service|<activity|<provider|<receiver" '
    exp_PermNotSet2 = ' | grep -e "exported=\\"true\\""'
    exp_PermNotSet3 = ' | grep -v "android:permission=\\""'
    exp_PermNotSet = exp_PermNotSet1 + and_manifest_path + exp_PermNotSet2 + exp_PermNotSet3
    cmd_and_pkg_permNotSet = subprocess.run(
        ["bash", "-c", exp_PermNotSet],
        capture_output=True, text=True
    )
    cmd_and_pkg_permNotSet_output = cmd_and_pkg_permNotSet.stdout
    logger.info(and_manifest_path)
    logger.info(cmd_and_pkg_permNotSet_output)

    if cmd_and_pkg_permNotSet_output.count("\n") > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that the appropriate Permission should be set via android:permission attribute with a proper android:protectionLevel in the AndroidManifest file, if observed. Please note that, The unprotected components can be invoked by other malicious applications and potentially access sensitive data or perform any of the privileged tasks possibly.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-1 | CWE-276: Incorrect Default Permissions")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - potential SQL Injection
    logger.info("\n==>> The potential SQL Injection instances...\n")
    countSqli = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_sqli = subprocess.run(
                ["grep", "-nr", "-e", ".rawQuery(", "-e", ".execSQL(", "-e", "appendWhere(", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_sqli_output = cmd_and_pkg_sqli.stdout
            if ".rawQuery(" in cmd_and_pkg_sqli_output or ".execSQL(" in cmd_and_pkg_sqli_output or ".appendWhere(" in cmd_and_pkg_sqli_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_sqli_output)
                countSqli += 1

    if countSqli > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that Prepared Statements are used or methods have been used securely to perform any sensitive tasks related to the databases, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - potential Cross-Site Scripting flaws
    logger.info("\n==>> The potential Cross-Site Scripting flaws...\n")
    countXSS = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_xss = subprocess.run(
                ["grep", "-nr", "-e", ".evaluateJavascript(", "-e", ".loadUrl('javascript:", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_xss_output = cmd_and_pkg_xss.stdout
            if "javascript" in cmd_and_pkg_xss_output or "evaluateJavascript" in cmd_and_pkg_xss_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_xss_output)
                countXSS += 1

    if countXSS > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that an appropriate encoding is applied to escape characters, such as HTML entity encoding, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - potential Code Execution flaws
    logger.info("\n==>> The potential Code Execution flaws...\n")
    countRCE = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_RCE = subprocess.run(
                ["grep", "-nr", "-e", "Runtime.getRuntime().exec(", "-e", "Runtime.getRuntime(", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_RCE_output = cmd_and_pkg_RCE.stdout
            if "getRuntime" in cmd_and_pkg_RCE_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_RCE_output)
                countRCE += 1

    if countRCE > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended not to execute the commands directly on the Operating System or to never use calls to native commands, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - Fragment Injection
    logger.info("\n==>> The Fragment Injection instances...\n")
    countPrefAct = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_prefActivity = subprocess.run(
                ["grep", "-nr", "-e", "extends PreferenceActivity", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_prefActivity_output = cmd_and_pkg_prefActivity.stdout
            if "PreferenceActivity" in cmd_and_pkg_prefActivity_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_prefActivity_output)
                countPrefAct += 1

    if countPrefAct > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to implement isValidFragment method or update the android:targetSdkVersion to 19 or higher, if observed. Please note that, With this vulnerability, an attacker can call fragments inside the target application or run the code present in other classes' constructors.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - EnableSafeBrowsing
    logger.info("\n==>> The EnableSafeBrowsing setting...\n")
    countSafeBrow = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            cmd_and_pkg_EnableSafeBrowsing = subprocess.run(
                ["grep", "-nr", "-F", "EnableSafeBrowsing", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_EnableSafeBrowsing_output = cmd_and_pkg_EnableSafeBrowsing.stdout
            if "EnableSafeBrowsing" in cmd_and_pkg_EnableSafeBrowsing_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_EnableSafeBrowsing_output)
                countSafeBrow += 1

    if countSafeBrow > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that EnableSafeBrowsing should be configured to true, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-940: Improper Verification of Source of a Communication Channel")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")


    # MASVS V6 - MSTG-PLATFORM-2 - potential Cross-Site Scripting Flaws
    logger.info("\n==>> The potential Cross-Site Scripting flaws...\n")
    countXSS = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_xss = subprocess.check_output(["grep", "-nr", "-e", ".evaluateJavascript(", "-e", ".loadUrl('javascript:", sources_file])
                cmd_and_pkg_xss_output = cmd_and_pkg_xss.decode('utf-8')
                if "javascript" in cmd_and_pkg_xss_output or "evaluateJavascript" in cmd_and_pkg_xss_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_xss_output)
                    countXSS += 1
            except subprocess.CalledProcessError:
                pass

    if countXSS > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that an appropriate encoding is applied to escape characters, such as HTML entity encoding, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - potential Code Execution Flaws
    logger.info("\n==>> The potential Code Execution flaws...\n")
    countRCE = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_RCE = subprocess.check_output(["grep", "-nr", "-e", "Runtime.getRuntime().exec(", "-e", "Runtime.getRuntime(", sources_file])
                cmd_and_pkg_RCE_output = cmd_and_pkg_RCE.decode('utf-8')
                if "getRuntime" in cmd_and_pkg_RCE_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_RCE_output)
                    countRCE += 1
            except subprocess.CalledProcessError:
                pass

    if countRCE > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended not to execute the commands directly on the Operating System or to never use calls to native commands, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - Fragment Injection
    logger.info("\n==>> The Fragment Injection instances...\n")
    countPrefAct = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_prefActivity = subprocess.check_output(["grep", "-nr", "-e", "extends PreferenceActivity", sources_file])
                cmd_and_pkg_prefActivity_output = cmd_and_pkg_prefActivity.decode('utf-8')
                if "PreferenceActivity" in cmd_and_pkg_prefActivity_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_prefActivity_output)
                    countPrefAct += 1
            except subprocess.CalledProcessError:
                pass

    if countPrefAct > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to implement isValidFragment method or update the android:targetSdkVersion to 19 or higher, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - potential Cross-Site Scripting Flaws
    logger.info("\n==>> The potential Cross-Site Scripting flaws...\n")
    countXSS = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_xss = subprocess.check_output(["grep", "-nr", "-e", ".evaluateJavascript(", "-e", ".loadUrl('javascript:", sources_file])
                cmd_and_pkg_xss_output = cmd_and_pkg_xss.decode('utf-8')
                if "javascript" in cmd_and_pkg_xss_output or "evaluateJavascript" in cmd_and_pkg_xss_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_xss_output)
                    countXSS += 1
            except subprocess.CalledProcessError:
                pass

    if countXSS > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that an appropriate encoding is applied to escape characters, such as HTML entity encoding, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - potential Code Execution Flaws
    logger.info("\n==>> The potential Code Execution flaws...\n")
    countRCE = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_RCE = subprocess.check_output(["grep", "-nr", "-e", "Runtime.getRuntime().exec(", "-e", "Runtime.getRuntime(", sources_file])
                cmd_and_pkg_RCE_output = cmd_and_pkg_RCE.decode('utf-8')
                if "getRuntime" in cmd_and_pkg_RCE_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_RCE_output)
                    countRCE += 1
            except subprocess.CalledProcessError:
                pass

    if countRCE > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended not to execute the commands directly on the Operating System or to never use calls to native commands, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - Fragment Injection
    logger.info("\n==>> The Fragment Injection instances...\n")
    countPrefAct = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_prefActivity = subprocess.check_output(["grep", "-nr", "-e", "extends PreferenceActivity", sources_file])
                cmd_and_pkg_prefActivity_output = cmd_and_pkg_prefActivity.decode('utf-8')
                if "PreferenceActivity" in cmd_and_pkg_prefActivity_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_prefActivity_output)
                    countPrefAct += 1
            except subprocess.CalledProcessError:
                pass

    if countPrefAct > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to implement isValidFragment method or update the android:targetSdkVersion to 19 or higher, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - EnableSafeBrowsing
    logger.info("\n==>> The EnableSafeBrowsing setting...\n")
    countSafeBrow = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            try:
                cmd_and_pkg_EnableSafeBrowsing = subprocess.check_output(["grep", "-nr", "-F", "EnableSafeBrowsing", sources_file])
                cmd_and_pkg_EnableSafeBrowsing_output = cmd_and_pkg_EnableSafeBrowsing.decode('utf-8')
                if "EnableSafeBrowsing" in cmd_and_pkg_EnableSafeBrowsing_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_EnableSafeBrowsing_output)
                    countSafeBrow += 1
            except subprocess.CalledProcessError:
                pass

    if countSafeBrow > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that EnableSafeBrowsing should be configured to true, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-940: Improper Verification of Source of a Communication Channel")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-2 - URL Loading in WebViews
    logger.info("\n==>> The instances of URL Loading in WebViews...\n")
    countUrlLoad = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_urlLoading = subprocess.check_output(["grep", "-nr", "-e", "shouldOverrideUrlLoading(", "-e", "shouldInterceptRequest(", sources_file])
                cmd_and_pkg_urlLoading_output = cmd_and_pkg_urlLoading.decode('utf-8')
                if "shouldOverrideUrlLoading" in cmd_and_pkg_urlLoading_output or "shouldInterceptRequest" in cmd_and_pkg_urlLoading_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_urlLoading_output)
                    countUrlLoad += 1
            except subprocess.CalledProcessError:
                pass

    if countUrlLoad > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to implement custom URL handlers securely, if observed. Please note that, Even if the attacker cannot bypass the checks on loading arbitrary URLs/domains, they may still be able to try to exploit the handlers.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-939: Improper Authorization in Handler for Custom URL Scheme")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-3 - Custom URL Schemes
    logger.info("\n==>> The Custom URL Schemes...\n")
    countCustUrlSch = 0
    for sources_file in files_res:
        if sources_file.endswith(".xml"):
            try:
                cmd_and_pkg_custUrlSchemes = subprocess.check_output(["grep", "-nr", "-e", "<intent-filter", "-e", "<data android:scheme", "-e", "<action android:name", sources_file])
                cmd_and_pkg_custUrlSchemes_output = cmd_and_pkg_custUrlSchemes.decode('utf-8')
                if "<intent-filter" in cmd_and_pkg_custUrlSchemes_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_custUrlSchemes_output)
                    countCustUrlSch += 1
            except subprocess.CalledProcessError:
                pass

    if countCustUrlSch > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that custom URL schemes should be configured with android:autoVerify=true, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-3 | CWE-927: Use of Implicit Intent for Sensitive Communication")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-4 - Implicit intent used for broadcast
    logger.info("\n==>> The Implicit intents used for broadcast...\n")
    countImpliIntBroad = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_impliIntBroad = subprocess.check_output(["grep", "-nr", "-e", "sendBroadcast(", "-e", "sendOrderedBroadcast(", "-e", "sendStickyBroadcast(", "-e", "new android.content.Intent", "-e", "new Intent(", sources_file])
                cmd_and_pkg_impliIntBroad_output = cmd_and_pkg_impliIntBroad.decode('utf-8')
                if "sendBroadcast(" in cmd_and_pkg_impliIntBroad_output or "sendOrderedBroadcast(" in cmd_and_pkg_impliIntBroad_output or "sendStickyBroadcast(" in cmd_and_pkg_impliIntBroad_output:
                    logger.info(sources_file)
                    logger.info(cmd_and_pkg_impliIntBroad_output)
                    countImpliIntBroad += 1
            except subprocess.CalledProcessError:
                pass

    if countImpliIntBroad > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to not send the broadcast using an implicit intent, if observed. Use methods such as sendBroadcast, sendOrderedBroadcast, sendStickyBroadcast, etc. appropriately. Please note that, an attacker can intercept or hijack the sensitive data among components. Always use explicit intents for broadcast components or LocalBroadcastManager and use an appropriate permission.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-4 | CWE-927: Use of Implicit Intent for Sensitive Communication")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-4 - Implicit intent used for activity
    logger.info("\n==>> The Implicit intents used for activity...\n")
    countImpliIntAct = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_impliIntAct = subprocess.run(
                ["grep", "-nr", "-e", "startActivity(", "-e", "startActivityForResult(", "-e", "new android.content.Intent", 
                "-e", "new Intent(", "-e", "setData(", "-e", "putExtra(", "-e", "setFlags(", "-e", "setAction(", 
                "-e", "addFlags(", "-e", "setDataAndType(", "-e", "addCategory(", "-e", "setClassName(", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_impliIntAct_output = cmd_and_pkg_impliIntAct.stdout
            if "startActivity(" in cmd_and_pkg_impliIntAct_output or "startActivityForResult(" in cmd_and_pkg_impliIntAct_output:
                logger.info(sources_file)
                if any(keyword in cmd_and_pkg_impliIntAct_output for keyword in ["startActivity", "new Intent(", "new android.content.Intent", 
                                                                                "setData(", "putExtra(", "setFlags(", "setAction(", 
                                                                                "addFlags(", "setDataAndType(", "addCategory(", "setClassName("]):
                    logger.info(cmd_and_pkg_impliIntAct_output)
                    countImpliIntAct += 1

    if countImpliIntAct > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to not start the activity using an implicit intent, if observed. Please note that, an attacker can hijack the activity and sometimes it may lead to sensitive information disclosure. Always use explicit intents to start activities using the setComponent, setPackage, setClass or setClassName methods of the Intent class.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-4 | CWE-927: Use of Implicit Intent for Sensitive Communication")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-5 - JavaScript Execution in WebViews
    logger.info("\n==>> The instances of JavaScript Execution in WebViews...\n")
    countSetJavScr = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_setJavaScriptEnabled = subprocess.run(
                ["grep", "-nri", "-e", "setJavaScriptEnabled(", "-e", "WebView", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_setJavaScriptEnabled_output = cmd_and_pkg_setJavaScriptEnabled.stdout
            if "setJavaScriptEnabled" in cmd_and_pkg_setJavaScriptEnabled_output:
                logger.info(sources_file)
                if "setJavaScriptEnabled" in cmd_and_pkg_setJavaScriptEnabled_output or "WebView" in cmd_and_pkg_setJavaScriptEnabled_output:
                    logger.info(cmd_and_pkg_setJavaScriptEnabled_output)
                    countSetJavScr += 1

    if countSetJavScr > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to implement JavaScript execution in WebViews securely, if observed. Please note that, depending on the permissions of the application, it may allow an attacker to interact with the different functionalities of the device.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-5 | CWE-749: Exposed Dangerous Method or Function")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-6 - Remote/Local URL load in WebViews
    logger.info("\n==>> The instances of Remote/Local URL load in WebViews...\n")
    countLoadURL = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_loadUrl = subprocess.run(
                ["grep", "-nr", "-e", ".loadUrl(", "-e", ".loadDataWithBaseURL(", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_loadUrl_output = cmd_and_pkg_loadUrl.stdout
            if ".loadUrl" in cmd_and_pkg_loadUrl_output or ".loadDataWithBaseURL" in cmd_and_pkg_loadUrl_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_loadUrl_output)
                countLoadURL += 1

    if countLoadURL > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to implement Remote/Local URL load in WebViews securely, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-940: Improper Verification of Source of a Communication Channel")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-6 - Hard-coded Links
    logger.info("\n==>> The Hard-coded links...\n")
    countExtLink = 0
    countExtLink2 = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_extLinks = subprocess.run(
                ["grep", "-nr", "-e", "://", sources_file],
                capture_output=True, text=True
            )
            cmd_and_pkg_extLinks_output = cmd_and_pkg_extLinks.stdout
            if "://" in cmd_and_pkg_extLinks_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_extLinks_output)
                countExtLink += 1
                countExtLink2 += cmd_and_pkg_extLinks_output.count("\n")

    if countExtLink > 0:
        logger.info(f"[+] Total file sources are: {countExtLink} & its total instances are: {countExtLink2}\n")
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that external/hard-coded links have been used wisely across the application, if observed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")



    # MASVS V6 - MSTG-PLATFORM-6 - Resource Access permissions
    logger.info("\n==>> The instances of Resource Access permissions...\n")
    countFileAccPerm = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_fileAccessPerm = subprocess.run(
                ["grep", "-nr", "-e", "setAllowFileAccess(", "-e", "setAllowFileAccessFromFileURLs(", 
                "-e", "setAllowUniversalAccessFromFileURLs(", "-e", "setAllowContentAccess(", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_and_pkg_fileAccessPerm_output = cmd_and_pkg_fileAccessPerm.stdout.decode()
            if "setAllowFileAccess" in cmd_and_pkg_fileAccessPerm_output or \
            "setAllowFileAccessFromFileURLs" in cmd_and_pkg_fileAccessPerm_output or \
            "setAllowUniversalAccessFromFileURLs" in cmd_and_pkg_fileAccessPerm_output or \
            "setAllowContentAccess" in cmd_and_pkg_fileAccessPerm_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_fileAccessPerm_output)
                countFileAccPerm += 1
    if countFileAccPerm > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to set Resource Access permissions as false, if observed. Please note that, those functions are quite dangerous as it allows Webview to read all the files that the application has access to.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-749: Exposed Dangerous Method or Function")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")


    # MASVS V6 - MSTG-PLATFORM-6 - Resource Access permissions
    logger.info("\n==>> The instances of Resource Access permissions...\n")
    countFileAccPerm = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_fileAccessPerm = subprocess.run(
                ["grep", "-nr", "-e", "setAllowFileAccess(", "-e", "setAllowFileAccessFromFileURLs(", 
                "-e", "setAllowUniversalAccessFromFileURLs(", "-e", "setAllowContentAccess(", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_and_pkg_fileAccessPerm_output = cmd_and_pkg_fileAccessPerm.stdout.decode()
            if "setAllowFileAccess" in cmd_and_pkg_fileAccessPerm_output or \
            "setAllowFileAccessFromFileURLs" in cmd_and_pkg_fileAccessPerm_output or \
            "setAllowUniversalAccessFromFileURLs" in cmd_and_pkg_fileAccessPerm_output or \
            "setAllowContentAccess" in cmd_and_pkg_fileAccessPerm_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_fileAccessPerm_output)
                countFileAccPerm += 1
    if countFileAccPerm > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to set Resource Access permissions as false, if observed. Please note that, those functions are quite dangerous as it allows Webview to read all the files that the application has access to.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-749: Exposed Dangerous Method or Function")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-6 - Remote WebView Debugging setting
    logger.info("\n==>> The Remote WebView Debugging setting...\n")
    countWebConDebug = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_webConDebug = subprocess.run(
                ["grep", "-nr", "-e", "setWebContentsDebuggingEnabled(", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_and_pkg_webConDebug_output = cmd_and_pkg_webConDebug.stdout.decode()
            if "setWebContentsDebuggingEnabled" in cmd_and_pkg_webConDebug_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_webConDebug_output)
                countWebConDebug += 1
    if countWebConDebug > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to disable setWebContentsDebuggingEnabled flag, if observed. Please note that, Remote WebView debugging can allow attackers to steal or corrupt the contents of WebViews loaded with web contents (HTML/CSS/JavaScript).")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-6 | CWE-215: Insertion of Sensitive Information Into Debugging Code")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-7 - Java Objects Are Exposed Through WebViews
    logger.info("\n==>> The instances of Java Objects exposure through WebViews...\n")
    countJavInt = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_addJavascriptInterface = subprocess.run(
                ["grep", "-nr", "-F", "addJavascriptInterface(", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_and_pkg_addJavascriptInterface_output = cmd_and_pkg_addJavascriptInterface.stdout.decode()
            if "addJavascriptInterface" in cmd_and_pkg_addJavascriptInterface_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_addJavascriptInterface_output)
                countJavInt += 1
    if countJavInt > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that only JavaScript provided with the APK should be allowed to use the bridges and no JavaScript should be loaded from remote endpoints, if observed. Please note that, this present a potential security risk if any sensitive data is being exposed through those interfaces.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-7 | CWE-749: Exposed Dangerous Method or Function")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")


    # MASVS V6 - MSTG-PLATFORM-8 - Object Persistence/Serialization
    logger.info("\n==>> The Object Persistence/Serialization instances...\n")
    countSerialize = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_serializable = subprocess.run(
                ["grep", "-nr", "-e", ".getSerializable(", "-e", ".getSerializableExtra(", "-e", "new Gson()", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_and_pkg_serializable_output = cmd_and_pkg_serializable.stdout.decode()
            if "getSerializable" in cmd_and_pkg_serializable_output or "Gson" in cmd_and_pkg_serializable_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_serializable_output)
                countSerialize += 1
    if countSerialize > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to use Serializable only when the serialized classes are stable, if observed. Reflection-based persistence should be avoided as the attacker might be able to manipulate it to execute business logic.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-8 | CWE-502: Deserialization of Untrusted Data")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V6 - MSTG-PLATFORM-10 - WebViews Cleanup
    logger.info("\n==>> The WebViews Cleanup implementation...\n")
    countWebViewCleanUp = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_webViewClean = subprocess.run(
                ["grep", "-nr", "-e", r"\.clearCache(", "-e", r"\.deleteAllData(", "-e", r"\.removeAllCookies(", 
                "-e", r"\.deleteRecursively(", "-e", r"\.clearFormData(", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_and_pkg_webViewClean_output = cmd_and_pkg_webViewClean.stdout.decode()
            if "clearCache" in cmd_and_pkg_webViewClean_output or "deleteAllData" in cmd_and_pkg_webViewClean_output or \
            "removeAllCookies" in cmd_and_pkg_webViewClean_output or "deleteRecursively" in cmd_and_pkg_webViewClean_output or \
            "clearFormData" in cmd_and_pkg_webViewClean_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_webViewClean_output)
                countWebViewCleanUp += 1
    if countWebViewCleanUp == 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended to clear the WebView resources when the application accesses any sensitive data within that, which may include any files stored locally, the RAM cache, and any loaded JavaScript. Please note that, this present a potential security risk if any sensitive data is being exposed.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS: MSTG-PLATFORM-10 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
    if countWebViewCleanUp > 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It seems that the application clears the data via some mechanism, if observed. Please note that, the application should clear all the WebView resources including any files stored locally, the RAM cache, and any loaded JavaScript when it accesses any sensitive data within a WebView.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS V6: MSTG-PLATFORM-10 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")

    # MASVS V1 - MSTG-ARCH-9 - AppUpdateManager
    logger.info("\n==>> The Application Update mechanism...\n")
    countAppUpManag = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            cmd_and_pkg_AppUpdateManager = subprocess.run(
                ["grep", "-nr", "-e", "AppUpdateManager", sources_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cmd_and_pkg_AppUpdateManager_output = cmd_and_pkg_AppUpdateManager.stdout.decode()
            if "AppUpdateManager" in cmd_and_pkg_AppUpdateManager_output:
                logger.info(sources_file)
                logger.info(cmd_and_pkg_AppUpdateManager_output)
                countAppUpManag += 1
    if countAppUpManag >= 0:
        logger.info("[!] QuickNote:")
        logger.info("    - It is recommended that applications should be forced to be updated. If a security update comes in, then AppUpdateType.IMMEDIATE flag should be used in order to make sure that the user cannot go forward with using the app without updating it. Please note that, newer versions of an application will not fix security issues that are living in the backends to which the app communicates.")
        logger.info("\n[*] Reference:")
        logger.info("    - OWASP MASVS V1: MSTG-ARCH-9 | CWE-1277: Firmware Not Updateable")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme")


    # MASVS V1 - MSTG-ARCH-9 - potential third-party application installation
    logger.info(f"{colorPurple}\n==>> The potential third-party application installation mechanism...\n{color_reset}")
    count_app_install = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_app_install = subprocess.check_output(
                    ["grep", "-nr", "-e", r"\.setDataAndType(", "-e", "application/vnd.android.package-archive", "-e", "FileProvider", "-e", "getFileDirPath(", "-e", "installApp(", sources_file])
                cmd_and_pkg_app_install_output = cmd_and_pkg_app_install.decode()
                if "vnd.android.package-archive" in cmd_and_pkg_app_install_output:
                    logger.info(colorBrown + sources_file + color_reset)
                    if ("setDataAndType(" in cmd_and_pkg_app_install_output or 
                            "application/vnd.android.package-archive" in cmd_and_pkg_app_install_output or 
                            "FileProvider" in cmd_and_pkg_app_install_output or 
                            "getFileDirPath" in cmd_and_pkg_app_install_output or 
                            "installApp" in cmd_and_pkg_app_install_output):
                        logger.info(cmd_and_pkg_app_install_output)
                        count_app_install += 1
            except subprocess.CalledProcessError:
                pass

    if count_app_install > 0:
        logger.info(colorCyan + "[!] QuickNote:" + color_reset)
        logger.info("    - It is recommended to install the application via Google Play and stop using local APK file installation, if observed. If it cannot be avoided, then make sure that the APK file should be stored in a private folder with no overwrite permission. Please note that, Attacker can install a malicious APK file if he/she can control the public folder or path.")
        logger.info(colorCyan + "\n[*] Reference:" + color_reset)
        logger.info("    - OWASP MASVS V1: MSTG-ARCH-9 | CWE-940: Improper Verification of Source of a Communication Channel")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x06-v1-architecture_design_and_threat_modelling_requireme")

    # MASVS V7 - MSTG-CODE-2 - AndroidManifest file - Package Debuggable
    logger.info(f"{colorPurple}\n==>> The debuggable flag configuration...\n{color_reset}")
    try:
        cmd_and_pkg_debug = subprocess.check_output(["grep", "-i", "android:debuggable", and_manifest_path])
        cmd_and_pkg_debug_output = cmd_and_pkg_debug.decode()
        cmd_and_pkg_debug_regex = re.compile(r'android:debuggable="true"')
        cmd_and_pkg_debug_regex_match = cmd_and_pkg_debug_regex.search(cmd_and_pkg_debug_output)
        if cmd_and_pkg_debug_regex_match is None:
            logger.info("    - android:debuggable=\"true\" flag has not been observed in the AndroidManifest.xml file.")
        else:
            logger.info(colorBrown + and_manifest_path + color_reset)
            logger.info(f"    - {cmd_and_pkg_debug_regex_match.group()}")
            logger.info(colorCyan + "\n[!] QuickNote:" + color_reset)
            logger.info("    - It is recommended not to enable the debuggable flag, if observed. Please note that, the enabled setting allows attackers to obtain access to sensitive information, control the application flow, etc.")
            logger.info(colorCyan + "\n[*] Reference:" + color_reset)
            logger.info("    - OWASP MASVS V7: MSTG-CODE-2 | CWE-215: Insertion of Sensitive Information Into Debugging Code")
            logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")
    except subprocess.CalledProcessError:
        pass

    # MASVS V7 - MSTG-CODE-4 - StrictMode
    logger.info(f"{colorPurple}\n==>> The StrictMode Policy instances...\n{color_reset}")
    count_strict_mode = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_strict_mode = subprocess.check_output(
                    ["grep", "-nr", "-e", "StrictMode.setThreadPolicy", "-e", "StrictMode.setVmPolicy", sources_file])
                cmd_and_pkg_strict_mode_output = cmd_and_pkg_strict_mode.decode()
                if "StrictMode" in cmd_and_pkg_strict_mode_output:
                    logger.info(colorBrown + sources_file + color_reset)
                    logger.info(cmd_and_pkg_strict_mode_output)
                    count_strict_mode += 1
            except subprocess.CalledProcessError:
                pass

    if count_strict_mode > 0:
        logger.info(colorCyan + "[!] QuickNote:" + color_reset)
        logger.info("    - It is recommended that StrictMode should not be enabled in a production application, if observed. Please note that, It is designed for pre-production use only.")
        logger.info(colorCyan + "\n[*] Reference:" + color_reset)
        logger.info("    - OWASP MASVS V7: MSTG-CODE-4 | CWE-749: Exposed Dangerous Method or Function")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")


    # MASVS V7 - MSTG-CODE-6 - Exception Handling
    logger.info(f"{colorPurple}\n==>> The Exception Handling instances...\n{colorReset}")
    countExcepHandl = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_StrictMode = subprocess.check_output(
                    ["grep", "-nr", "-e", r" RuntimeException(", "-e", "UncaughtExceptionHandler(", sources_file])
                cmd_and_pkg_Exception_output = cmd_and_pkg_StrictMode.decode()
                if "Exception" in cmd_and_pkg_Exception_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_Exception_output)
                    countExcepHandl += 1
            except subprocess.CalledProcessError:
                pass

    if countExcepHandl > 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It is recommended that a well-designed and unified scheme to handle exceptions, if observed. Please note that, The application should not expose any sensitive data while handling exceptions in its UI or log-statements.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V7: MSTG-CODE-6 | CWE-755: Improper Handling of Exceptional Conditions")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")

    # MASVS V7 - MSTG-CODE-9 - Obfuscated Code
    logger.info(f"{colorPurple}\n==>> The Obfuscated Code blocks...\n{colorReset}")
    countObfusc = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_packageObfuscate = subprocess.check_output(
                    ["grep", "-nr", "-F", "package com.a.", sources_file])
                cmd_and_pkg_importObfuscate = subprocess.check_output(
                    ["grep", "-nr", "-F", "import com.a.", sources_file])
                cmd_and_pkg_classObfuscate = subprocess.check_output(
                    ["grep", "-nr", "-F", "class a$b", sources_file])
                
                cmd_and_pkg_packageObfuscate_output = cmd_and_pkg_packageObfuscate.decode()
                if "package" in cmd_and_pkg_packageObfuscate_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_packageObfuscate_output)
                    countObfusc += 1
                    
                cmd_and_pkg_importObfuscate_output = cmd_and_pkg_importObfuscate.decode()
                if "import" in cmd_and_pkg_importObfuscate_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_importObfuscate_output)
                    countObfusc += 1
                    
                cmd_and_pkg_classObfuscate_output = cmd_and_pkg_classObfuscate.decode()
                if "class" in cmd_and_pkg_classObfuscate_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_classObfuscate_output)
                    countObfusc += 1
            except subprocess.CalledProcessError:
                pass

    if countObfusc == 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It is recommended that some basic obfuscation should be implemented to the release byte-code, if not observed. Please note that, Code obfuscation in the applications protects against reverse engineering, tampering, or other attacks.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V7: MSTG-CODE-9 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")

    if countObfusc > 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It seems that code obfuscation has been identified. It is recommended to check it out manually as well for better clarity.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V7: MSTG-CODE-9 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x12-v7-code_quality_and_build_setting_requirements")


    # OWASP MASVS - V8: Resilience Requirements
    logger.info(f"{colorBlueBold}\n[+] Hunting begins based on \"V8: Resilience Requirements\"{colorReset}")
    logger.info("[+] -----------------------------------------------------")

    # MASVS V8 - MSTG-RESILIENCE-1 - Root Detection
    logger.info(f"{colorPurple}\n==>> The Root Detection implementation...\n{colorReset}")
    countRootDetect = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_rootDetect = subprocess.check_output(
                    ["grep", "-nr", "-e", "supersu", "-e", "superuser", "-e", "/xbin/", "-e", "/sbin/", sources_file])
                cmd_and_pkg_rootDetect_output = cmd_and_pkg_rootDetect.decode()
                if "super" in cmd_and_pkg_rootDetect_output or "bin/" in cmd_and_pkg_rootDetect_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_rootDetect_output)
                    countRootDetect += 1
            except subprocess.CalledProcessError:
                pass

    if countRootDetect == 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It is recommended to implement root detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-1 | CWE-250: Execution with Unnecessary Privileges")
        logger.info("    - https://mas.owasp.org/MASVS/")

    if countRootDetect > 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It seems that root detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-1 | CWE-250: Execution with Unnecessary Privileges")
        logger.info("    - https://mas.owasp.org/MASVS/")

    # MASVS V8 - MSTG-RESILIENCE-2 - Anti-Debugging Detection
    logger.info(f"{colorPurple}\n==>> The Anti-Debugging Detection implementation...\n{colorReset}")
    countDebugDetect = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_debugDetect = subprocess.check_output(
                    ["grep", "-nr", "-e", "isDebuggable", "-e", "isDebuggerConnected", sources_file])
                cmd_and_pkg_debugDetect_output = cmd_and_pkg_debugDetect.decode()
                if "Debug" in cmd_and_pkg_debugDetect_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_debugDetect_output)
                    countDebugDetect += 1
            except subprocess.CalledProcessError:
                pass

    if countDebugDetect == 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It is recommended to implement Anti-Debugging detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-2 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mas.owasp.org/MASVS/")

    if countDebugDetect > 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It seems that Anti-Debugging detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-2 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mas.owasp.org/MASVS/")


    # MASVS V8 - MSTG-RESILIENCE-3 - File Integrity Checks
    logger.info(f"{colorPurple}\n==>> The File Integrity Checks implementation...\n{colorReset}")
    countIntCheck = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_intCheck = subprocess.check_output(
                    ["grep", "-nr", "-e", ".getEntry('classes", sources_file])
                cmd_and_pkg_intCheck_output = cmd_and_pkg_intCheck.decode()
                if "classes" in cmd_and_pkg_intCheck_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_intCheck_output)
                    countIntCheck += 1
            except subprocess.CalledProcessError:
                pass

    if countIntCheck == 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It is recommended to implement CRC checks on the app bytecode, native libraries, and important data files, if not observed. Please note that, reverse engineers can easily bypass APK code signature check by re-packaging and re-signing an app. The idea is to have additional controls in place so that the app only runs correctly in its unmodified state, even if the code signature is valid.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-3 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mas.owasp.org/MASVS/")

    if countIntCheck > 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It seems that CRC checks have been implemented on the app bytecode. Please note that, The idea is to have additional controls in place so that the app only runs correctly in its unmodified state, even if the code signature is valid. It is recommended to check it out manually as well for better clarity.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-3 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mas.owasp.org/MASVS/")

    # MASVS V8 - MSTG-RESILIENCE-5 - Emulator Detection
    logger.info(f"{colorPurple}\n==>> The Emulator Detection implementation...\n{colorReset}")
    countEmulatorDetect = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_emulatorDetect = subprocess.check_output(
                    ["grep", "-nr", "-E", "Build.MODEL.contains\\(|Build.MANUFACTURER.contains\\(|Build.HARDWARE.contains\\(|Build.PRODUCT.contains\\(|/genyd", sources_file])
                cmd_and_pkg_emulatorDetect_output = cmd_and_pkg_emulatorDetect.decode()
                if "Build" in cmd_and_pkg_emulatorDetect_output or "genyd" in cmd_and_pkg_emulatorDetect_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_emulatorDetect_output)
                    countEmulatorDetect += 1
            except subprocess.CalledProcessError:
                pass

    if countEmulatorDetect == 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It is recommended to implement Emulator detection mechanisms in the application, if not observed. Please note that, Multiple detection methods should be implemented so that it cannot be bypassed easily.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-5 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mas.owasp.org/MASVS/")

    if countEmulatorDetect > 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It seems that Emulator detection mechanism has been implemented. Please note that, Multiple detection methods should be implemented. It is recommended to check it out manually as well for better clarity.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-5 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mas.owasp.org/MASVS/")



    # MASVS V8 - MSTG-RESILIENCE-7 - Defence Mechanisms
    logger.info(f"{colorPurple}\n==>> The implementation of any Defence Mechanisms...\n{colorReset}")
    countDefenceMech = 0
    for sources_file in files:
        if sources_file.endswith(".java"):
            try:
                cmd_and_pkg_defenceMech = subprocess.check_output(
                    ["grep", "-nr", "-e", "SafetyNetClient", sources_file])
                cmd_and_pkg_defenceMech_output = cmd_and_pkg_defenceMech.decode()
                if "SafetyNetClient" in cmd_and_pkg_defenceMech_output:
                    logger.info(colorBrown + sources_file + colorReset)
                    logger.info(cmd_and_pkg_defenceMech_output)
                    countDefenceMech += 1
            except subprocess.CalledProcessError:
                pass

    if countDefenceMech == 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It is recommended to implement various defence mechanisms such as SafetyNet Attestation API, if not observed.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-7 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mas.owasp.org/MASVS/")

    if countDefenceMech > 0:
        logger.info(colorCyan + "[!] QuickNote:" + colorReset)
        logger.info("    - It seems that SafetyNet APIs have been implemented as part of the various defensive mechanisms.")
        logger.info(colorCyan + "\n[*] Reference:" + colorReset)
        logger.info("    - OWASP MASVS V8: MSTG-RESILIENCE-7 | CWE-693: Protection Mechanism Failure")
        logger.info("    - https://mas.owasp.org/MASVS/")

    # End of scan
    end_time = time.time()
    logger.info(f"\n[+] Scan has been finished at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")

    start_time = time.time()  # You should initialize start_time earlier in the code
    logger.info(f"\n[+] Total time taken for hunting: {round(end_time - start_time, 2)} seconds")

    logger.info(f"{color_blue_bold}\n[*] Thank you for using SecDroid :))\n{colorReset}")


def main():
    # If no arguments are provided, show intro and a help message.
    if len(sys.argv) == 1:
        SecDroid_Intro()
        print("\n[!] Kindly provide valid arguments/path. Use -h for help.")
        sys.exit(0)

    # Show help if "-h" is provided anywhere in the arguments.
    if "-h" in sys.argv:
        SecDroid_Intro()
        SecDroid_help()
        sys.exit(0)

    # Determine if logging should be enabled
    use_logging = "-l" in sys.argv

    # Remove the logging flag from the argument list to simplify further processing.
    args = [arg for arg in sys.argv[1:] if arg != "-l"]

    # The first argument should be the command: either "-p" (single APK) or "-m" (multiple APKs).
    command = args[0]
    if command not in ["-p", "-m"]:
        SecDroid_Intro()
        print("\n[!] Invalid argument. Use -h for help.")
        sys.exit(0)

    # Initialize logger (if logging is enabled)
    logger = None
    if use_logging:
        log_file_path = os.path.join(os.getcwd(), f"SecDroid_{time.strftime('%Y-%m-%d_%H-%M-%S')}.txt")
        logging.basicConfig(
            filename=log_file_path,
            filemode="w",
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.INFO
        )
        logger = logging.getLogger("SecDroidLogger")
        logger.info("======================================")
        logger.info(f"SecDroid Logging Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Log File: {log_file_path}")
        logger.info("======================================")

    # Process single APK case.
    if command == "-p":
        if len(args) < 2:
            SecDroid_Intro()
            print("\n[!] Kindly provide a valid APK path for the -p option.")
            sys.exit(0)
        
        apk_path = args[1]
        SecDroid_Intro(logger)
        if use_logging:
            logger.info(f"Processing single APK: {apk_path}")

        # Process the APK
        SecDroid_core(apk_path, logger)
        sys.exit(0)

    # Process multiple APKs in a folder.
    if command == "-m":
        if len(args) < 2:
            SecDroid_Intro()
            print("\n[!] Kindly provide a valid folder path for the -m option.")
            sys.exit(0)

        folder_path = args[1]
        SecDroid_Intro(logger)

        if not os.path.exists(folder_path):
            print(f"\n[!] Given path '{folder_path}' does not exist. Exiting...")
            sys.exit(0)

        # Get all APK files in the folder.
        apk_files = glob.glob(os.path.join(folder_path, "*.apk"))
        count_apk = len(apk_files)
        print(f"\n==>> Total number of APK files: {count_apk}\n")
        if count_apk == 0:
            print("[!] No APK files found. Exiting...")
            sys.exit(0)

        print("==>> List of APK files:")
        for i, apk in enumerate(apk_files, start=1):
            print(f"    {i}. {os.path.basename(apk)}")

        # Process each APK.
        for i, apk_path in enumerate(apk_files, start=1):
            print(f"\n==>> Scanning app {i} - {os.path.basename(apk_path)}")
            if use_logging:
                logger.info(f"Scanning app {i}: {apk_path}")
            SecDroid_core(apk_path, logger)

        sys.exit(0)

if __name__ == "__main__":
    main()
